import { describe, expect, it } from 'vitest';
import { budgetMs } from '../../test/perf';
import { matchFindings, renamer, type Trackable } from './match';

const item = (overrides: Partial<Trackable>): Trackable => ({
  ruleKey: 'eslint:no-console',
  path: 'src/a.ts',
  lineHash: 'L1',
  contextHash: 'C1',
  line: 10,
  column: 1,
  message: 'Unexpected console statement.',
  closed: false,
  ...overrides,
});

const pairs = (m: Map<number, number>) => [...m.entries()].sort((a, b) => a[0] - b[0]);

describe('matchFindings (data-model.md §5.2)', () => {
  it('matches an unchanged finding whose code moved by any number of lines (pass 1)', () => {
    for (const shift of [1, 20, 500, -9]) {
      expect(pairs(matchFindings([item({ line: 10 + shift })], [item({ line: 10 })]))).toEqual([
        [0, 0],
      ]);
    }
  });

  it('prefers stronger evidence: pass 1 beats a pass 2 candidate that is closer', () => {
    const findings = [item({ line: 10 })];
    const candidates = [item({ line: 10, contextHash: 'other' }), item({ line: 90 })];
    expect(pairs(matchFindings(findings, candidates))).toEqual([[0, 1]]);
  });

  it('falls back to pass 3 (same line and message) and pass 4 (same context) for an edited line', () => {
    const edited = item({ lineHash: 'L-edited', contextHash: 'C-edited', line: 10 });
    expect(pairs(matchFindings([edited], [item({ line: 10 })]))).toEqual([[0, 0]]);
    const reworded = item({ lineHash: 'L-edited', message: 'changed', line: 14 });
    expect(pairs(matchFindings([reworded], [item({ line: 10 })]))).toEqual([[0, 0]]);
  });

  it('never matches across rules or paths, and leaves unrelated items unmatched', () => {
    const findings = [item({ ruleKey: 'eslint:eqeqeq' }), item({ path: 'src/b.ts' })];
    expect(matchFindings(findings, [item({})]).size).toBe(0);
  });

  it('pairs identical findings by the smallest |Δline| first', () => {
    const findings = [item({ line: 52 }), item({ line: 12 })];
    const candidates = [item({ line: 10 }), item({ line: 50 }), item({ line: 200 })];
    expect(pairs(matchFindings(findings, candidates))).toEqual([
      [0, 1],
      [1, 0],
    ]);
  });

  it('matches 10 000 identical findings in one file without creating or losing any', () => {
    const n = 10_000;
    const candidates = Array.from({ length: n }, (_, i) => item({ line: 10 + i * 5 }));
    // A 2-line shift (less than half the spacing): every finding keeps its own issue.
    const shifted = Array.from({ length: n }, (_, i) => item({ line: 12 + i * 5 }));
    const started = performance.now();
    const matched = matchFindings(shifted, candidates);
    expect(performance.now() - started).toBeLessThan(budgetMs(5_000));
    for (let i = 0; i < n; i++) expect(matched.get(i)).toBe(i);
    // 20 lines inserted above all of them: indistinguishable issues may trade places (ruling
    // T3), but every finding is matched, so nothing is closed and nothing is new.
    const moved = Array.from({ length: n }, (_, i) => item({ line: 30 + i * 5 }));
    const all = matchFindings(moved, candidates);
    expect(all.size).toBe(n);
    expect(new Set(all.values()).size).toBe(n);
  });

  it('matches file-less findings on their rule and message', () => {
    const fileless = item({ path: null, line: null, lineHash: 'H', contextHash: 'H' });
    expect(pairs(matchFindings([fileless], [fileless]))).toEqual([[0, 0]]);
  });

  it('rewrites candidate paths through scm.renames (step 0)', () => {
    const rename = renamer([{ from: 'src/old.ts', to: 'src/new.ts' }]);
    expect(rename('src/old.ts')).toBe('src/new.ts');
    expect(rename('src/other.ts')).toBe('src/other.ts');
    expect(rename(null)).toBeNull();
  });

  it('interleaves same-line findings by column so identical hashes never swap identities (U5 fix round 1, #1)', () => {
    // Two different findings on the same line share a line/context hash (the hash is computed
    // from the line text, not the column), so only their column tells them apart.
    const a = item({ column: 5, message: "'a' is defined but never used." });
    const b = item({ column: 12, message: "'b' is defined but never used." });
    expect(pairs(matchFindings([a, b], [a, b]))).toEqual([
      [0, 0],
      [1, 1],
    ]);
    // The outcome must not depend on the (arbitrary, DB-query-order-derived) candidate order.
    expect(pairs(matchFindings([a, b], [b, a]))).toEqual([
      [0, 1],
      [1, 0],
    ]);
  });

  it('prefers a non-closed candidate over a closed one at equal distance (#4)', () => {
    const target = item({ line: 10 });
    const closedCandidate = item({ line: 8, closed: true });
    const openCandidate = item({ line: 12, closed: false });
    expect(pairs(matchFindings([target], [closedCandidate, openCandidate]))).toEqual([[0, 1]]);
    expect(pairs(matchFindings([target], [openCandidate, closedCandidate]))).toEqual([[0, 0]]);
  });

  it('preserves identity of same-line, same-hash findings across a shift, when their messages differ (U5 fix round 2, #1)', () => {
    const a = item({ line: 10, column: 5, message: "'a' is defined but never used." });
    const b = item({ line: 10, column: 12, message: "'b' is defined but never used." });
    for (const shift of [-1, 1, 20]) {
      const shiftedA = { ...a, line: a.line! + shift };
      const shiftedB = { ...b, line: b.line! + shift };
      expect(pairs(matchFindings([shiftedA, shiftedB], [a, b]))).toEqual([
        [0, 0],
        [1, 1],
      ]);
      // Must not depend on candidate array order (loadCandidates' own order is deterministic,
      // but nothing about matching should rely on that beyond being deterministic).
      expect(pairs(matchFindings([shiftedA, shiftedB], [b, a]))).toEqual([
        [0, 1],
        [1, 0],
      ]);
    }
  });

  it('is a deterministic bijection for fully identical findings, whichever candidate order is given (U5 fix round 2, #1)', () => {
    // Same line, same column, same everything: genuinely indistinguishable. Any pairing is
    // acceptable, but it must be a real bijection (no finding lost or double-matched) and it must
    // not depend on which candidate the caller happened to list first.
    const a = item({ line: 10, column: 5 });
    const b = item({ line: 10, column: 5 });
    for (const candidates of [
      [a, b],
      [b, a],
    ]) {
      const matched = matchFindings([a, b], candidates);
      expect(matched.size).toBe(2);
      expect(new Set(matched.values()).size).toBe(2);
      expect(matchFindings([a, b], candidates)).toEqual(matched); // repeatable, not random
    }
  });

  it('prefers a non-closed candidate over a closed one even when both sit on the same side of the finding (U5 fix round 2, #2)', () => {
    const target = item({ line: 11 });
    const openCandidate = item({ line: 10, closed: false });
    const closedCandidate = item({ line: 10, closed: true });
    expect(pairs(matchFindings([target], [closedCandidate, openCandidate]))).toEqual([[0, 1]]);
    expect(pairs(matchFindings([target], [openCandidate, closedCandidate]))).toEqual([[0, 0]]);
  });

  it('never leaves a matchable pair unmatched just because a rank layer had no partner (U5 fix round 3, #A)', () => {
    // Same rule/path/contextHash only (pass 4). f0 lines up with c0 on line 10; f1 has no
    // partner on its own line and must still be matched to whatever candidate is left (c1, one
    // line down), not stranded unmatched: a line group with items left over stays in the sweep.
    const f0 = item({ lineHash: 'La', line: 10, column: 1, message: 'm-f0' });
    const f1 = item({ lineHash: 'Lb', line: 10, column: 5, message: 'm-f1' });
    const c0 = item({ lineHash: 'Lc', line: 10, column: 1, message: 'm-c0' });
    const c1 = item({ lineHash: 'Ld', line: 12, column: 9, message: 'm-c1' });
    expect(pairs(matchFindings([f0, f1], [c0, c1]))).toEqual([
      [0, 0],
      [1, 1],
    ]);
  });

  it('aligns lines with differing counts by column, so the extra item is the one left over, not the last one (U5 fix round 3, #B)', () => {
    // A genuinely new finding (column 1) appears above two pre-existing ones (columns 5 and 9).
    // Pairing by position (0th, 1st, 2nd) would shift every finding out of alignment with the
    // candidates; the order-preserving alignment (smallest column shift) matches the two that
    // really correspond and leaves only the new one unmatched.
    const f0 = item({ line: 10, column: 1 }); // new
    const f1 = item({ line: 10, column: 5 });
    const f2 = item({ line: 10, column: 9 });
    const c0 = item({ line: 10, column: 5 });
    const c1 = item({ line: 10, column: 9 });
    expect(pairs(matchFindings([f0, f1, f2], [c0, c1]))).toEqual([
      [1, 0],
      [2, 1],
    ]);

    const g0 = item({ line: 10, column: 5 });
    const g1 = item({ line: 10, column: 9 });
    const d0 = item({ line: 10, column: 9 });
    expect(pairs(matchFindings([g0, g1], [d0]))).toEqual([[1, 0]]);
  });

  it(
    'matches 100 000 identical findings without creating or losing any (100k performance sanity check, U5 fix round 3)',
    () => {
      const n = 100_000;
      const candidates = Array.from({ length: n }, (_, i) => item({ line: 10 + i * 5 }));
      const shifted = Array.from({ length: n }, (_, i) => item({ line: 12 + i * 5 }));
      const started = performance.now();
      const matched = matchFindings(shifted, candidates);
      expect(performance.now() - started).toBeLessThan(budgetMs(15_000));
      expect(matched.size).toBe(n);
      expect(new Set(matched.values()).size).toBe(n);
      for (let i = 0; i < n; i++) expect(matched.get(i)).toBe(i);
    },
    budgetMs(30_000),
  );

  describe('pairing inside a bucket is order-preserving and robust to shifts and re-indents (U5 fix round 4)', () => {
    // One rule, one message, identical hashes unless a test says otherwise: only line and column
    // can tell these apart.
    const x = (line: number, column: number, extra: Partial<Trackable> = {}) =>
      item({ line, column, message: 'x', ...extra });

    it('keeps two identical same-line findings apart when the line shifts, with a different-message twin beside them', () => {
      const y = (line: number, message = 'y') => item({ line, column: 12, message });
      const expected = [
        [0, 0],
        [1, 1],
        [2, 2],
      ];
      expect(
        pairs(matchFindings([x(13, 5), x(13, 9), y(13)], [x(10, 5), x(10, 9), y(10)])),
      ).toEqual(expected);
      // The twin's message changed too, so it falls through to pass 1 on its own.
      expect(
        pairs(matchFindings([x(13, 5), x(13, 9), y(13, 'y2')], [x(10, 5), x(10, 9), y(10)])),
      ).toEqual(expected);
      expect(
        pairs(matchFindings([x(13, 5), x(13, 9), y(13)], [y(10), x(10, 9), x(10, 5)])),
      ).toEqual([
        [0, 2],
        [1, 1],
        [2, 0],
      ]);
    });

    it('matches a moved finding, not a new identical one further away', () => {
      expect(pairs(matchFindings([x(5, 5), x(12, 5)], [x(10, 5)]))).toEqual([[1, 0]]);
      expect(pairs(matchFindings([x(3, 5), x(12, 5), x(12, 9)], [x(10, 5), x(10, 9)]))).toEqual([
        [1, 0],
        [2, 1],
      ]);
    });

    it('keeps a same-line pair in order when the line is re-indented and shifted (P1, P3)', () => {
      // lineHash/contextHash ignore whitespace (report-format.md §7.3): a re-indent keeps every
      // hash but moves every column, so absolute columns must not decide the pairing.
      expect(pairs(matchFindings([x(11, 3), x(11, 7)], [x(10, 1), x(10, 5)]))).toEqual([
        [0, 0],
        [1, 1],
      ]);
      // Re-indented by +4 and shifted up a line: finding 0's new column equals candidate 1's old
      // one, which an exact-column match would wrongly pair.
      expect(pairs(matchFindings([x(7, 9), x(7, 13)], [x(8, 5), x(8, 9)]))).toEqual([
        [0, 0],
        [1, 1],
      ]);
    });

    it('keeps a same-line pair in order in the weaker passes too (P1b: pass 4, the line itself edited)', () => {
      const findings = [x(11, 1, { lineHash: 'N' }), x(11, 5, { lineHash: 'N' })];
      const candidates = [x(10, 1, { lineHash: 'O' }), x(10, 5, { lineHash: 'O' })];
      expect(pairs(matchFindings(findings, candidates))).toEqual([
        [0, 0],
        [1, 1],
      ]);
      expect(pairs(matchFindings(findings, [...candidates].reverse()))).toEqual([
        [0, 1],
        [1, 0],
      ]);
    });

    it('never lets a far candidate that merely keeps the same column steal a near one (P2)', () => {
      // Re-indented and its context changed (so pass 2, lineHash only): the nearby issue is the
      // same code; the one 490 lines away just happens to sit at the finding's new column.
      const finding = x(11, 9, { contextHash: 'C-new' });
      const near = x(10, 5, { contextHash: 'C-a' });
      const far = x(500, 9, { contextHash: 'C-b' });
      expect(pairs(matchFindings([finding], [near, far]))).toEqual([[0, 0]]);
      expect(pairs(matchFindings([finding], [far, near]))).toEqual([[0, 1]]);
    });

    it('prefers a nearby line with exactly the same layout over an equally near one without it', () => {
      // Identical text at two indentations (inside and outside a block): the one whose columns
      // match is the same code, as long as it is within a few lines.
      const finding = x(20, 5);
      expect(pairs(matchFindings([finding], [x(19, 1), x(22, 5)]))).toEqual([[0, 1]]);
      // Beyond the layout penalty, distance wins again.
      expect(pairs(matchFindings([finding], [x(19, 1), x(40, 5)]))).toEqual([[0, 0]]);
    });

    it('leaves over the item a count mismatch actually removed, by column, in any pass (P4)', () => {
      // One finding, two candidates on the next line (pass 4: the line was edited): the one at
      // the finding's column is its counterpart.
      const finding = x(10, 9, { lineHash: 'N' });
      const candidates = [x(11, 1, { lineHash: 'O1' }), x(11, 9, { lineHash: 'O2' })];
      expect(pairs(matchFindings([finding], candidates))).toEqual([[0, 1]]);
      // A re-indented line that lost one item: the uniform shift (+2) is found and the survivor
      // keeps its identity.
      expect(pairs(matchFindings([x(11, 7), x(11, 11)], [x(10, 1), x(10, 5), x(10, 9)]))).toEqual([
        [0, 1],
        [1, 2],
      ]);
    });

    it('matches every finding it can when counts differ on a line, whichever pass it is (maximality)', () => {
      const f0 = item({ line: 10, column: 1, lineHash: 'L1', message: 'a' });
      const f1 = item({ line: 10, column: 5, lineHash: 'L1', message: 'b' });
      const c0 = item({ line: 10, column: 1, lineHash: 'L2', message: 'c' });
      const c1 = item({ line: 11, column: 1, lineHash: 'L3', message: 'd' });
      expect(matchFindings([f0, f1], [c0, c1]).size).toBe(2);
    });

    it('gives the same pairing, by content, for every order of the candidates', () => {
      const findings = [x(11, 5), x(11, 9), x(11, 9), item({ line: 11, column: 12 }), x(40, 5)];
      const candidates = [
        x(10, 5),
        x(10, 9),
        x(10, 9),
        item({ line: 10, column: 12 }),
        x(38, 5),
        x(10, 5, { closed: true }),
      ];
      const permutations = (a: number[]): number[][] =>
        a.length <= 1
          ? [a]
          : a.flatMap((v, i) =>
              permutations([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [v, ...p]),
            );
      const outcomes = new Set<string>();
      for (const order of permutations(candidates.map((_, i) => i))) {
        const matched = matchFindings(
          findings,
          order.map((i) => candidates[i]!),
        );
        // Identical candidates are interchangeable, so compare what each finding got by content.
        outcomes.add(
          JSON.stringify(
            pairs(matched).map(([f, c]) => [f, JSON.stringify(candidates[order[c]!])]),
          ),
        );
      }
      expect(outcomes.size).toBe(1);
    });

    it(
      'stays O(n log n) with 100 000 findings on lines whose counts differ from the candidates',
      () => {
        const n = 100_000;
        const findings = Array.from({ length: n }, (_, i) =>
          x(Math.floor(i / 7) * 2 + 1, (i % 7) * 3 + 1, { message: `m${i % 2}` }),
        );
        const candidates = Array.from({ length: n }, (_, i) =>
          x(Math.floor(i / 9) * 2 + 2, (i % 9) * 5 + 1, { message: `m${i % 3}` }),
        );
        const started = performance.now();
        const matched = matchFindings(findings, candidates);
        expect(performance.now() - started).toBeLessThan(budgetMs(15_000));
        expect(matched.size).toBe(n);
        expect(new Set(matched.values()).size).toBe(n);
      },
      budgetMs(30_000),
    );

    it('keeps every identity when an identical finding is prepended to a line of k (k = 8, 9, 40, 63; U5 fix round 5)', () => {
      // E.g. a new parameter with the same no-explicit-any warning inserted before k others: the
      // line's text changed, so this is the lineHash-free pass 4, and only the columns of the
      // existing k findings stayed put.
      for (const k of [8, 9, 40, 63]) {
        const candidates = Array.from({ length: k }, (_, i) =>
          x(10, 10 + i * 4, { lineHash: 'old' }),
        );
        const findings = [
          x(10, 2, { lineHash: 'new' }),
          ...candidates.map((c) => ({ ...c, lineHash: 'new' })),
        ];
        const expected = candidates.map((_, i) => [i + 1, i]);
        expect(pairs(matchFindings(findings, candidates)), `k = ${k}`).toEqual(expected);
      }
    });

    it('on equal |Δcolumn|, pairs a lone finding with the candidate to its right (the negative shift, as round 4 did)', () => {
      // Two candidates equally far left and right of the finding's column: the item that moved
      // left (the candidate to the right) wins, whichever order the candidates arrive in.
      const finding = x(10, 9);
      expect(pairs(matchFindings([finding], [x(11, 5), x(11, 13)]))).toEqual([[0, 1]]);
      expect(pairs(matchFindings([finding], [x(11, 13), x(11, 5)]))).toEqual([[0, 0]]);
      // The other way round (one candidate, two findings): the finding to its left.
      expect(pairs(matchFindings([x(11, 5), x(11, 13)], [x(10, 9)]))).toEqual([[0, 0]]);
    });

    it('re-indents a line of more than 8 items that lost one, keeping every identity (first-to-first and last-to-last shifts)', () => {
      // Beyond SHIFT_SEARCH_LIMIT only a few shifts are tried; a uniform re-indent must still
      // align exactly, whichever item was removed. (+4, one item spacing, with the middle item
      // removed is the reviewer's probe. With an end item removed, a re-indent by s is
      // indistinguishable from removing the other end and re-indenting by s ± 4, and the smaller
      // |s| rightly wins, so the ends are checked with +1.)
      const cases = [9, 20, 64].flatMap((k) => [
        { k, removed: Math.floor(k / 2), indent: 4 },
        ...[0, Math.floor(k / 2), k - 1].map((removed) => ({ k, removed, indent: 1 })),
      ]);
      for (const { k, removed, indent } of cases) {
        {
          const candidates = Array.from({ length: k }, (_, i) => x(10, 1 + i * 4));
          const keep = candidates.map((_, i) => i).filter((i) => i !== removed);
          const findings = keep.map((i) => x(11, 1 + indent + i * 4));
          expect(
            pairs(matchFindings(findings, candidates)),
            `k = ${k}, removed ${removed}, +${indent}`,
          ).toEqual(keep.map((c, f) => [f, c]));
          // And the reverse: an item added to a re-indented line.
          expect(
            pairs(matchFindings(candidates, findings)),
            `k = ${k}, added ${removed}, +${indent}`,
          ).toEqual(keep.map((c, f) => [c, f]));
        }
      }
    });

    it("builds a line's layout from live candidates only, so a closed issue's stale position cannot hide the right match", () => {
      const finding = x(10, 5);
      const open = x(10, 5);
      const closedStale = x(10, 9, { closed: true });
      const decoy = x(12, 5);
      expect(pairs(matchFindings([finding], [open, closedStale, decoy]))).toEqual([[0, 0]]);
      expect(pairs(matchFindings([finding], [decoy, closedStale, open]))).toEqual([[0, 2]]);
    });

    it('pairs one huge line group against many single-item lines in linear time (50 000 each way)', () => {
      // A minified file now vs a formatted one before, and the reverse: every pairing takes one
      // item off the big group, which must cost O(1), not O(|group|).
      const n = 50_000;
      const oneLine = Array.from({ length: n }, (_, i) => x(1, i + 1));
      const manyLines = Array.from({ length: n }, (_, i) => x(i + 1, 1));
      for (const [findings, candidates] of [
        [oneLine, manyLines],
        [manyLines, oneLine],
      ] as const) {
        const started = performance.now();
        const matched = matchFindings(findings, candidates);
        expect(performance.now() - started).toBeLessThan(budgetMs(1_000));
        expect(matched.size).toBe(n);
      }
    });

    it('bounds the alignment work: a 64-item line against 20 000 single-item lines', () => {
      const n = 20_000;
      const findings = Array.from({ length: 64 }, (_, i) => x(1, i * 3 + 1));
      const candidates = Array.from({ length: n }, (_, i) => x(i + 2, (i % 64) * 3 + 1));
      const started = performance.now();
      const matched = matchFindings(findings, candidates);
      expect(performance.now() - started).toBeLessThan(budgetMs(1_000));
      expect(matched.size).toBe(64);
    });
  });
});
