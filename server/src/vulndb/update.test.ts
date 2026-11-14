import { describe, expect, it } from 'vitest';
import { VULNDB_LEASE_MS } from './update';

describe('the vulnerability worker', () => {
  it('holds a 5-minute lease, so a crashed worker blocks the next re-check for minutes, not half an hour', () => {
    expect(VULNDB_LEASE_MS).toBe(5 * 60_000);
  });
});
