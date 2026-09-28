/**
 * A wall-clock budget for a performance test (the same rule as `server/test/perf.ts`, which this
 * package cannot import). The budgets guard against complexity regressions, not micro-timings;
 * vitest.config.ts sets `QUALOR_TEST_TIME_SCALE` (5 under `--coverage`, else 1), and a slow
 * machine can raise it.
 */
export function budgetMs(ms: number): number {
  const scale = Number(process.env['QUALOR_TEST_TIME_SCALE'] ?? '1');
  return ms * (Number.isFinite(scale) && scale > 0 ? scale : 1);
}
