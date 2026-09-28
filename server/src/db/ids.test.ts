import { describe, expect, it } from 'vitest';
import { uuidv7, uuidv7Timestamp } from './ids';

describe('uuidv7', () => {
  it('has the RFC 9562 version-7 layout', () => {
    expect(uuidv7()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('encodes the current millisecond', () => {
    const before = Date.now();
    const ts = uuidv7Timestamp(uuidv7());
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(Date.now() + 1);
  });

  it('is strictly increasing within one millisecond, across counter overflow', () => {
    const now = Date.now();
    const ids = Array.from({ length: 5_000 }, () => uuidv7(now));
    expect([...ids].sort()).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('never goes backwards when the clock does', () => {
    const later = uuidv7(Date.now() + 5_000);
    const earlier = uuidv7(Date.now());
    expect(earlier > later).toBe(true);
  });
});
