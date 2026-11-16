import { describe, expect, it } from 'vitest';
import type { Executor } from '../db/client';
import { upsertVersion } from './store';

/**
 * A transaction whose read finds no version and whose upsert never returns a row (a writer that
 * keeps winning the race): counts the upserts, and stops a runaway loop at 10.
 */
function racingTx() {
  const seen = { upserts: 0 };
  const tx = {
    select: () => ({ from: () => ({ where: () => ({ for: () => Promise.resolve([]) }) }) }),
    insert: () => ({
      values: () => ({
        onConflictDoUpdate: () => ({
          returning: () => {
            if (++seen.upserts > 10) return Promise.reject(new Error('unbounded retries'));
            return Promise.resolve([]);
          },
        }),
      }),
    }),
  } as unknown as Executor;
  return { tx, seen };
}

describe('upsertVersion', () => {
  it('reads the version again once when the upsert returns no row, then gives up (t5m1)', async () => {
    const { tx, seen } = racingTx();
    await expect(
      upsertVersion(tx, {
        projectId: '0190a6c2-0000-7000-8000-000000000001',
        label: '1.0.0',
        source: 'tag',
        tag: 'v1.0.0',
        analysisId: '0190a6c2-0000-7000-8000-000000000002',
        analyzedAt: new Date(Date.UTC(2026, 10, 1)),
      }),
    ).rejects.toThrow(/version 1\.0\.0 .*after a second read/);
    expect(seen.upserts).toBe(2);
  });
});
