import { describe, expect, it } from 'vitest';
import { MAX_RETRY_AFTER_SECONDS, retryAfterSeconds } from './retry-after';

describe('retryAfterSeconds (GitLab, GitHub, Jira, Microsoft Entra, Azure DevOps)', () => {
  it('reads RateLimit-Reset when there is no Retry-After, and clamps both', () => {
    const now = Date.UTC(2026, 8, 25, 9, 0, 0);
    expect(retryAfterSeconds({ 'ratelimit-reset': String(now / 1000 + 30) }, now)).toBe(30);
    expect(retryAfterSeconds({ 'retry-after': '0' }, now)).toBe(1);
    expect(retryAfterSeconds({ 'retry-after': '86400' }, now)).toBe(MAX_RETRY_AFTER_SECONDS);
    expect(retryAfterSeconds({ 'retry-after': new Date(now + 5_000).toUTCString() }, now)).toBe(5);
    expect(retryAfterSeconds({}, now)).toBeNull();
  });

  it('clamps to 15 minutes', () => {
    expect(MAX_RETRY_AFTER_SECONDS).toBe(900);
  });
});
