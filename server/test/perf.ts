import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';

/**
 * A wall-clock budget for a performance test. These budgets guard against complexity
 * regressions (a quadratic path turning 50 ms into 20 s), not micro-timings, but instrumentation
 * such as v8 coverage slows hot loops several-fold. vitest.config.ts sets
 * `QUALOR_TEST_TIME_SCALE` (5 under `--coverage`, else 1); a slow machine can raise it.
 */
export function budgetMs(ms: number): number {
  const scale = Number(process.env.QUALOR_TEST_TIME_SCALE ?? '1');
  return ms * (Number.isFinite(scale) && scale > 0 ? scale : 1);
}

let gc: (() => void) | undefined;

/**
 * Runs a full garbage collection, so a heap measurement taken next reflects live objects, not
 * whatever garbage earlier tests left behind. Uses `global.gc` when node runs with
 * `--expose-gc`, else enables the flag at run time and takes `gc` from a fresh context.
 */
export function collectGarbage(): void {
  if (!gc) {
    const exposed = (globalThis as { gc?: () => void }).gc;
    if (exposed) gc = exposed;
    else {
      setFlagsFromString('--expose-gc');
      gc = runInNewContext('gc') as () => void;
    }
  }
  gc();
}
