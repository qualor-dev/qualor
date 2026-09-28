import { describe, expect, it } from 'vitest';
import {
  generateCases,
  identityErrors,
  rng,
  strandedPairs,
  type TruthFinding,
} from '../../test/match-harness';
import { matchFindings, type Trackable } from './match';

/**
 * Seeded property test for the matcher (data-model.md §5.2; U5 fix rounds 4–5), over randomly
 * edited files whose true finding identities are known (test/match-harness.ts; 1 500 distinct
 * cases per seed).
 *
 * `maxErrors` is an exact baseline: the current matcher's measured identity-error count on each
 * seed, with no headroom. The matcher is deterministic, so any change to it that moves these
 * numbers must re-baseline them here (lower is better; a rise needs a stated reason). The same
 * cases scored with the earlier designs (fix rounds of the task-4/5 report, and the final fix
 * wave):
 *
 * | seed | round 2 | round 3 | round 4 | round 5 | final wave (this) |
 * |------|---------|---------|---------|---------|-------------------|
 * | 1    | 1 040   | 885     | 470     | 502     | 483               |
 * | 2    | 1 141   | 951     | 508     | 537     | 519               |
 * | 3    | 1 039   | 780     | 414     | 441     | 428               |
 * | 42   | 1 106   | 800     | 456     | 488     | 476               |
 *
 * Round 5 rose over round 4 for two reasons. (1) It stopped searching shifts when the short side
 * of a line holds one item, and its shift-0 alignment then broke equal-|Δcolumn| ties towards the
 * left candidate instead of the right one (the negative shift); the final wave restores round 4's
 * choice, which accounts for 19/18/13/12 errors. (2) It builds candidate layouts from live
 * candidates only (round 5, #4); the harness closes some candidates without moving them, so it
 * rewards mixing their positions into the layouts, which real, stale closed positions would not.
 * That accounts for the remaining 13/11/14/20 over round 4 and is kept deliberately. (The final
 * wave's other change, extra shifts for lines beyond SHIFT_SEARCH_LIMIT, does not move these
 * numbers: the harness never puts that many items on one line.)
 *
 * Some errors are unavoidable: the tiny vocabulary makes many findings genuinely
 * indistinguishable from the hashes, lines and columns the matcher sees.
 */
const SEEDS = [
  { seed: 1, maxErrors: 483 },
  { seed: 2, maxErrors: 519 },
  { seed: 3, maxErrors: 428 },
  { seed: 42, maxErrors: 476 },
];
const CASES_PER_SEED = 1_500;

const PASS_KEYS: readonly ((t: Trackable) => string)[] = [
  (t) => `${t.lineHash}|${t.contextHash}|${t.message}`,
  (t) => `${t.lineHash}|${t.contextHash}`,
  (t) => t.lineHash,
  (t) => `${t.line}|${t.message}`,
  (t) => t.contextHash,
];

/** What the matcher can see of a candidate (no ground-truth token). */
const visible = ({ token, ...rest }: TruthFinding): string => {
  void token;
  return JSON.stringify(rest);
};

describe('matchFindings on randomly edited files (U5 fix round 4)', () => {
  for (const { seed, maxErrors } of SEEDS) {
    it(`seed ${seed}: a bijection within pass buckets, nothing stranded, deterministic, at most ${maxErrors} identity errors`, () => {
      const shuffle = rng(seed * 7919);
      let errors = 0;
      for (const { findings, candidates } of generateCases(seed, CASES_PER_SEED)) {
        const matched = matchFindings(findings, candidates);

        expect(new Set(matched.values()).size).toBe(matched.size);
        for (const [f, c] of matched) {
          const finding = findings[f]!;
          const candidate = candidates[c]!;
          expect(candidate.ruleKey).toBe(finding.ruleKey);
          expect(PASS_KEYS.some((key) => key(finding) === key(candidate))).toBe(true);
        }
        expect(strandedPairs(findings, candidates, matched)).toBe(0);

        // The same result, by content, whatever order the candidates arrive in.
        const order = candidates.map((_, i) => i);
        for (let i = order.length - 1; i > 0; i--) {
          const j = shuffle.int(i + 1);
          [order[i], order[j]] = [order[j]!, order[i]!];
        }
        const reordered = matchFindings(
          findings,
          order.map((i) => candidates[i]!),
        );
        const byContent = (m: ReadonlyMap<number, number>, at: (c: number) => TruthFinding) =>
          [...m].sort((a, b) => a[0] - b[0]).map(([f, c]) => [f, visible(at(c))]);
        expect(byContent(reordered, (c) => candidates[order[c]!]!)).toEqual(
          byContent(matched, (c) => candidates[c]!),
        );

        errors += identityErrors(findings, candidates, matched);
      }
      expect(errors).toBeLessThanOrEqual(maxErrors);
    });
  }
});
