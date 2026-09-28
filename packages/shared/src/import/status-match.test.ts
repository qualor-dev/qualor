import { describe, expect, it } from 'vitest';
import { budgetMs } from '../../test/perf';
import {
  IMPORT_COMMENT_LABELS,
  importCommentHeader,
  importCommentKey,
  matchStatuses,
  sanitizeImportComment,
  STATUS_IMPORT_MAX_CANDIDATES,
  STATUS_IMPORT_MAX_ITEMS,
  statusMatchItem,
  type StatusCandidate,
  type StatusItem,
} from './status-match';

const item = (ref: string, over: Partial<StatusItem> = {}): StatusItem => ({
  ref,
  ruleKeys: ['eslint:eqeqeq'],
  path: 'src/a.ts',
  line: 10,
  sonarLineHash: null,
  message: null,
  status: 'false_positive',
  ...over,
});
const cand = (id: string, over: Partial<StatusCandidate> = {}): StatusCandidate => ({
  id,
  ruleKey: 'eslint:eqeqeq',
  path: 'src/a.ts',
  line: 10,
  sonarLineHash: null,
  message: 'm',
  ...over,
});
const pairs = (items: StatusItem[], cands: StatusCandidate[]) =>
  Object.fromEntries(
    matchStatuses(items, cands).map((m) => [m.ref, m.ambiguous ? 'ambiguous' : m.candidateId]),
  );

/** A small deterministic PRNG (mulberry32), so the shuffles are reproducible. */
function prng(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function shuffle<T>(list: readonly T[], rnd: () => number): T[] {
  const out = [...list];
  for (let n = out.length - 1; n > 0; n--) {
    const k = Math.floor(rnd() * (n + 1));
    [out[n], out[k]] = [out[k]!, out[n]!];
  }
  return out;
}
/** The full result keyed by ref, so two runs compare regardless of the item order. */
const byRef = (items: StatusItem[], cands: StatusCandidate[]) =>
  Object.fromEntries(matchStatuses(items, cands).map((m) => [m.ref, m]));

describe('matchStatuses (import-sonarqube.md §10.4)', () => {
  it('pairs on rule, path and line (pass 1), preferring the message too (pass 0)', () => {
    const r = matchStatuses([item('s1', { message: 'm' })], [cand('c1')]);
    expect(r).toEqual([
      { ref: 's1', candidateId: 'c1', pass: 0, ambiguous: false, competitorsUnknown: false },
    ]);
    expect(matchStatuses([item('s1')], [cand('c1')])[0]?.pass).toBe(1);
  });

  it('needs the rule to be one of the targets and the same path', () => {
    expect(pairs([item('s1')], [cand('c1', { ruleKey: 'eslint:no-var' })])).toEqual({ s1: null });
    expect(pairs([item('s1')], [cand('c1', { path: 'src/b.ts' })])).toEqual({ s1: null });
  });

  it('refuses a same-line pair whose known hashes differ', () => {
    expect(
      pairs(
        [item('s1', { sonarLineHash: 'a'.repeat(32) })],
        [cand('c1', { sonarLineHash: 'b'.repeat(32) })],
      ),
    ).toEqual({ s1: null });
  });

  it('follows moved code by the line hash (pass 2), nearest first', () => {
    const h = 'a'.repeat(32);
    const r = matchStatuses(
      [item('s1', { line: 10, sonarLineHash: h })],
      [cand('far', { line: 90, sonarLineHash: h }), cand('near', { line: 14, sonarLineHash: h })],
    );
    expect(r[0]).toMatchObject({ candidateId: 'near', pass: 2 });
  });

  it('falls back to the message within 20 lines (pass 3), and no farther', () => {
    expect(
      matchStatuses([item('s1', { message: 'm' })], [cand('c1', { line: 30 })])[0],
    ).toMatchObject({ candidateId: 'c1', pass: 3 });
    expect(pairs([item('s1', { message: 'm' })], [cand('c1', { line: 31 })])).toEqual({
      s1: null,
    });
  });

  it('pairs one to one: a candidate is used once', () => {
    expect(pairs([item('s1'), item('s2')], [cand('c1')])).toEqual({ s1: 'c1', s2: null });
  });

  it('pairs identical items asking the same status in order (S6)', () => {
    // Both issues get false_positive whichever item is paired with which.
    expect(pairs([item('s1'), item('s2')], [cand('c2'), cand('c1')])).toEqual({
      s1: 'c1',
      s2: 'c2',
    });
  });

  it('marks a group ambiguous when its items ask for different statuses', () => {
    expect(
      pairs([item('s1'), item('s2', { status: 'wont_fix' })], [cand('c1'), cand('c2')]),
    ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    expect(pairs([item('s1'), item('s2', { status: 'wont_fix' })], [cand('c1')])).toEqual({
      s1: 'ambiguous',
      s2: 'ambiguous',
    });
  });

  it('matches file-less issues by rule', () => {
    expect(
      pairs([item('s1', { path: null, line: null })], [cand('c1', { path: null, line: null })]),
    ).toEqual({ s1: 'c1' });
  });

  it('does not depend on the order of items or candidates', () => {
    const h = 'c'.repeat(32);
    const items = [
      item('s1', { line: 3 }),
      item('s2', { line: 5, sonarLineHash: h }),
      item('s3', { line: 40, message: 'm' }),
      item('s4', { path: 'src/b.ts', line: 1 }),
    ];
    const cands = [
      cand('c1', { line: 3 }),
      cand('c2', { line: 9, sonarLineHash: h }),
      cand('c3', { line: 55 }),
      cand('c4', { path: 'src/b.ts', line: 1 }),
    ];
    const expected = pairs(items, cands);
    expect(expected).toEqual({ s1: 'c1', s2: 'c2', s3: 'c3', s4: 'c4' });
    expect(pairs([...items].reverse(), [...cands].reverse())).toEqual(expected);
  });

  it('stays fast at the request bounds (1 000 items, 20 000 candidates on 1 000 paths)', () => {
    const items = Array.from({ length: 1000 }, (_, n) =>
      item(`s${n}`, { path: `f${n}.ts`, line: (n % 50) + 1, message: 'm' }),
    );
    const cands = Array.from({ length: 20_000 }, (_, n) =>
      cand(`c${n}`, { path: `f${n % 1000}.ts`, line: (n % 97) + 1 }),
    );
    const started = performance.now();
    matchStatuses(items, cands);
    expect(performance.now() - started).toBeLessThan(budgetMs(2000));
  });

  describe('unknown line hashes (ruling S1)', () => {
    const h = 'a'.repeat(32);

    it('treats an empty hash as unknown on the same line: it neither refuses nor proves', () => {
      expect(
        pairs([item('s1', { sonarLineHash: h })], [cand('c1', { sonarLineHash: '' })]),
      ).toEqual({ s1: 'c1' });
      expect(
        pairs([item('s1', { sonarLineHash: '' })], [cand('c1', { sonarLineHash: h })]),
      ).toEqual({ s1: 'c1' });
    });

    it('never follows moved code by an empty or missing hash (pass 2)', () => {
      expect(
        pairs(
          [item('s1', { line: 10, sonarLineHash: '' })],
          [cand('c1', { line: 50, sonarLineHash: '' })],
        ),
      ).toEqual({ s1: null });
      expect(
        pairs(
          [item('s1', { line: 10, sonarLineHash: null })],
          [cand('c1', { line: 50, sonarLineHash: null })],
        ),
      ).toEqual({ s1: null });
    });

    it('groups an empty hash with a missing one: the same evidence', () => {
      expect(
        pairs(
          [
            item('s1', { sonarLineHash: '' }),
            item('s2', { sonarLineHash: null, status: 'wont_fix' }),
          ],
          [cand('c1'), cand('c2')],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });
  });

  describe('ambiguity is reported, never resolved by picking one', () => {
    it('marks items of different groups ambiguous when they compete for the same candidates', () => {
      // Different known hashes, one candidate whose hash is unknown: both are equally plausible.
      expect(
        pairs(
          [
            item('s1', { sonarLineHash: 'a'.repeat(32) }),
            item('s2', { sonarLineHash: 'b'.repeat(32), status: 'wont_fix' }),
          ],
          [cand('c1')],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
      // Overlapping targets on the same line.
      expect(
        pairs(
          [
            item('s1', { ruleKeys: ['eslint:eqeqeq'] }),
            item('s2', { ruleKeys: ['eslint:eqeqeq', 'eslint:no-var'], status: 'wont_fix' }),
          ],
          [cand('c1')],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    it('keeps an ambiguous candidate out of the weaker passes', () => {
      // s3 would take c1 by its message in pass 3; c1 is contested, so it is left alone.
      expect(
        pairs(
          [item('s1'), item('s2', { status: 'wont_fix' }), item('s3', { line: 15, message: 'm' })],
          [cand('c1')],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous', s3: null });
    });

    it('marks a tie in distance between different statuses ambiguous (pass 2)', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [
            item('s1', { line: 10, sonarLineHash: h }),
            item('s2', { line: 20, sonarLineHash: h, status: 'wont_fix' }),
          ],
          [cand('c1', { line: 15, sonarLineHash: h })],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    it('marks a tie in distance between different statuses ambiguous (pass 3)', () => {
      expect(
        pairs(
          [
            item('s1', { line: 10, message: 'm' }),
            item('s2', { line: 20, message: 'm', status: 'wont_fix' }),
          ],
          [cand('c1', { line: 15 })],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    it('contests a candidate that different statuses reach at any distance (pass 3)', () => {
      // s1 is nearer, but s2 reaches c1 too: nothing says which one c1 is.
      expect(
        pairs(
          [
            item('s1', { line: 10, message: 'm' }),
            item('s2', { line: 21, message: 'm', status: 'wont_fix' }),
          ],
          [cand('c1', { line: 15 })],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    it('contests a candidate that different statuses reach at any distance (pass 2)', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [
            item('fp', { line: 10, sonarLineHash: h }),
            item('wf', { line: 15, sonarLineHash: h, status: 'wont_fix' }),
          ],
          [cand('c1', { line: 12, sonarLineHash: h })],
        ),
      ).toEqual({ fp: 'ambiguous', wf: 'ambiguous' });
    });

    it('leaves an item alone whose nearer candidate is not contested', () => {
      // c2 is contested (s2 and s3 reach it), but s1 pairs with c1 before it gets that far.
      expect(
        pairs(
          [
            item('s1', { line: 10, message: 'm' }),
            item('s2', { line: 30, message: 'm' }),
            item('s3', { line: 40, message: 'm', status: 'wont_fix' }),
          ],
          [cand('c1', { line: 11 }), cand('c2', { line: 25 })],
        ),
      ).toEqual({ s1: 'c1', s2: 'ambiguous', s3: 'ambiguous' });
    });

    it('prefers the stronger pass: a message match beats a same-line match', () => {
      expect(
        pairs(
          [item('s1', { message: 'm' }), item('s2', { message: 'other', status: 'wont_fix' })],
          [cand('c1')],
        ),
      ).toEqual({ s1: 'c1', s2: null });
    });

    it('breaks a tie between items asking the same status by content, not by input order', () => {
      const items = [
        item('s2', { line: 20, message: 'm' }),
        item('s1', { line: 10, message: 'm' }),
      ];
      const cands = [cand('c1', { line: 15 })];
      expect(pairs(items, cands)).toEqual({ s1: 'c1', s2: null });
      expect(pairs([...items].reverse(), cands)).toEqual({ s1: 'c1', s2: null });
    });
  });

  describe('more candidates than items is ambiguous (ruling S2)', () => {
    it('in pass 0: two issues with the same line and message for one item', () => {
      expect(pairs([item('s1', { message: 'm' })], [cand('c2'), cand('c1')])).toEqual({
        s1: 'ambiguous',
      });
    });

    it('in pass 1: two issues on the item’s line, whatever their order', () => {
      expect(pairs([item('s1')], [cand('c2'), cand('c1')])).toEqual({ s1: 'ambiguous' });
      expect(pairs([item('s1')], [cand('c1'), cand('c2')])).toEqual({ s1: 'ambiguous' });
      // Ruling S6: as many candidates as items, all asking one status and each reaching every
      // candidate, is not a surplus: both candidates get that status whatever the pairing.
      expect(pairs([item('s1'), item('s2')], [cand('c1'), cand('c2')])).toEqual({
        s1: 'c1',
        s2: 'c2',
      });
    });

    it('in pass 2: two issues with the item’s hash at the same distance', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [item('s1', { line: 10, sonarLineHash: h })],
          [cand('up', { line: 5, sonarLineHash: h }), cand('down', { line: 15, sonarLineHash: h })],
        ),
      ).toEqual({ s1: 'ambiguous' });
    });

    it('in pass 3: two issues with the item’s message at the same distance', () => {
      expect(
        pairs(
          [item('s1', { line: 10, message: 'm' })],
          [cand('up', { line: 5 }), cand('down', { line: 15 })],
        ),
      ).toEqual({ s1: 'ambiguous' });
    });

    it('across a chain of items: 2 items reaching 3 candidates', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [item('s1', { line: 11, sonarLineHash: h }), item('s2', { line: 13, sonarLineHash: h })],
          [10, 12, 14].map((line) => cand(`c${line}`, { line, sonarLineHash: h })),
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    it('holds the surplus candidates back from the weaker passes', () => {
      // c1 and c2 are both on s1's line; s2 would take c1 by its message in pass 3.
      expect(
        pairs(
          [item('s1'), item('s2', { line: 15, message: 'm' })],
          [cand('c1'), cand('c2', { message: 'other' })],
        ),
      ).toEqual({ s1: 'ambiguous', s2: null });
    });

    it('never picks the wrong one of `import { a, b }` (one false positive, one open sibling)', () => {
      const h = 'a'.repeat(32);
      const sq = (ref: string, over: Partial<StatusItem> = {}) =>
        item(ref, {
          ruleKeys: ['typescript:S1128', '@typescript-eslint/no-unused-vars'],
          path: 'a.ts',
          line: 1,
          sonarLineHash: h,
          message: `Remove this unused import of '${ref}'.`,
          ...over,
        });
      const q = (id: string, name: string) =>
        cand(id, {
          ruleKey: '@typescript-eslint/no-unused-vars',
          path: 'a.ts',
          line: 1,
          sonarLineHash: h,
          message: `'${name}' is defined but never used.`,
        });
      for (const cands of [
        [q('q-a', 'a'), q('q-b', 'b')],
        [q('q1', 'b'), q('q0', 'a')],
      ]) {
        // Without competitors: two issues for one item.
        expect(pairs([sq('b')], cands)).toEqual({ b: 'ambiguous' });
        // With the open sibling as a competitor: the statuses differ.
        expect(pairs([sq('b'), sq('a', { status: 'open' })], cands)).toEqual({
          b: 'ambiguous',
          a: 'ambiguous',
        });
      }
    });
  });

  describe('each item decides for itself (ruling S5)', () => {
    /** Three issues of three rules on one line; s1 may be any of them, s2 and s3 only the third. */
    const lopsided = (s3: Partial<StatusItem> = {}) => ({
      items: [
        item('s1', { ruleKeys: ['r:a', 'r:b', 'r:c'] }),
        item('s2', { ruleKeys: ['r:c'] }),
        item('s3', { ruleKeys: ['r:c'], ...s3 }),
      ],
      cands: [
        cand('c1', { ruleKey: 'r:a' }),
        cand('c2', { ruleKey: 'r:b' }),
        cand('c3', { ruleKey: 'r:c' }),
      ],
    });

    it('holds back an item left with two candidates once the others’ only options are gone', () => {
      // s1 → {c1, c2, c3}, s2 → {c3}, s3 → {c3}: without c3, s1 still has c1 and c2, so it is
      // ambiguous and never paired with c1. s2 and s3 ask the same status for the one c3: the
      // first by content pairs, the other is unmatched (the rule for surplus items).
      const { items, cands } = lopsided();
      expect(pairs(items, cands)).toEqual({ s1: 'ambiguous', s2: 'c3', s3: null });
      const rnd = prng(7);
      for (let run = 0; run < 50; run++) {
        expect(pairs(shuffle(items, rnd), shuffle(cands, rnd))).toEqual({
          s1: 'ambiguous',
          s2: 'c3',
          s3: null,
        });
      }
    });

    it('keeps s2 and s3 apart by distinct evidence, and the mixed-status rule for them', () => {
      // Distinct known hashes (c3's unknown): two groups, the same outcome.
      const { items, cands } = lopsided({ sonarLineHash: 'b'.repeat(32) });
      expect(pairs(items, cands)).toEqual({ s1: 'ambiguous', s2: 'c3', s3: null });
      // s3 asks another status: the whole component is ambiguous, as before.
      const mixed = lopsided({ status: 'wont_fix' });
      expect(pairs(mixed.items, mixed.cands)).toEqual({
        s1: 'ambiguous',
        s2: 'ambiguous',
        s3: 'ambiguous',
      });
    });

    it('holds back the candidates of an ambiguous item from the weaker passes', () => {
      // s4 would take c1 by its message in pass 3; s1 held it back.
      const { items, cands } = lopsided();
      expect(
        pairs([...items, item('s4', { ruleKeys: ['r:a'], line: 15, message: 'm' })], cands),
      ).toEqual({ s1: 'ambiguous', s2: 'c3', s3: null, s4: null });
    });

    it('pairs an item whose other candidates are the only options of other items', () => {
      // s1 → {c1, c2}, s2 → {c2}: without c2, s1 has c1 alone.
      expect(
        pairs(
          [item('s1', { ruleKeys: ['r:a', 'r:b'] }), item('s2', { ruleKeys: ['r:b'] })],
          [cand('c1', { ruleKey: 'r:a' }), cand('c2', { ruleKey: 'r:b' })],
        ),
      ).toEqual({ s1: 'c1', s2: 'c2' });
    });

    it('holds back an item that has nothing left once the others’ only options are gone', () => {
      // s1 → {c1, c2}, s2 → {c1}, s3 → {c2}: s1 has no candidate of its own.
      expect(
        pairs(
          [
            item('s1', { ruleKeys: ['r:a', 'r:b'] }),
            item('s2', { ruleKeys: ['r:a'] }),
            item('s3', { ruleKeys: ['r:b'] }),
          ],
          [cand('c1', { ruleKey: 'r:a' }), cand('c2', { ruleKey: 'r:b' })],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'c1', s3: 'c2' });
    });

    it('still pairs a clean one-to-one request', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [
            item('s1', { line: 3 }),
            item('s2', { line: 10, message: 'm' }),
            item('s3', { line: 20, sonarLineHash: h }),
            item('s4', { line: 40, message: 'm' }),
          ],
          [
            cand('c1', { line: 3 }),
            cand('c2', { line: 10 }),
            cand('c3', { line: 27, sonarLineHash: h }),
            cand('c4', { line: 44 }),
          ],
        ),
      ).toEqual({ s1: 'c1', s2: 'c2', s3: 'c3', s4: 'c4' });
    });

    it('pairs by message on the same line when both hashes are known and differ (pass 3)', () => {
      // Passes 0 and 1 refuse the pair (the line was edited); the rule and message still agree.
      const r = matchStatuses(
        [item('s1', { sonarLineHash: 'a'.repeat(32), message: 'm' })],
        [cand('c1', { sonarLineHash: 'b'.repeat(32) })],
      );
      expect(r[0]).toMatchObject({ candidateId: 'c1', pass: 3, ambiguous: false });
    });
  });

  describe('a full pairing when it cannot matter (ruling S6)', () => {
    /** `import { a, b }`: two issues of one rule on one line, both marked false positive. */
    const both = (over: Partial<StatusItem> = {}) => ({
      items: [item('a', { message: 'm' }), item('b', { message: 'm', ...over })],
      cands: [cand('ca'), cand('cb')],
    });

    it('pairs both items of `import { a, b }` marked false positive', () => {
      const { items, cands } = both();
      const r = byRef(items, cands);
      expect(r['a']).toMatchObject({ candidateId: 'ca', pass: 0, ambiguous: false });
      expect(r['b']).toMatchObject({ candidateId: 'cb', pass: 0, ambiguous: false });
      const rnd = prng(11);
      for (let run = 0; run < 20; run++) {
        expect(pairs(shuffle(items, rnd), shuffle(cands, rnd))).toEqual({ a: 'ca', b: 'cb' });
      }
    });

    it('turns ambiguous with one open competitor in the component', () => {
      const { items, cands } = both();
      expect(
        pairs([...items, item('o', { message: 'm', status: 'open' })], [...cands, cand('cc')]),
      ).toEqual({ a: 'ambiguous', b: 'ambiguous', o: 'ambiguous' });
    });

    it('does not apply with an item marked competitorsUnknown (each item decides, S5)', () => {
      const { items, cands } = both({ competitorsUnknown: true });
      expect(pairs(items, cands)).toEqual({ a: 'ambiguous', b: 'ambiguous' });
    });

    it('leaves the items over the candidates unpaired', () => {
      expect(pairs([item('s1'), item('s2'), item('s3')], [cand('c2'), cand('c1')])).toEqual({
        s1: 'c1',
        s2: 'c2',
        s3: null,
      });
    });

    it('does not apply when one item cannot reach every candidate', () => {
      // s2 reaches only c2: S5 pairs s1 with c1 and s2 with c2, as before.
      expect(
        pairs(
          [item('s1', { ruleKeys: ['r:a', 'r:b'] }), item('s2', { ruleKeys: ['r:b'] })],
          [cand('c1', { ruleKey: 'r:a' }), cand('c2', { ruleKey: 'r:b' })],
        ),
      ).toEqual({ s1: 'c1', s2: 'c2' });
      // s1 reaches c1, c2 and c3; s2 and s3 only c3: s1 stays ambiguous (S5).
      expect(
        pairs(
          [
            item('s1', { ruleKeys: ['r:a', 'r:b', 'r:c'] }),
            item('s2', { ruleKeys: ['r:c'] }),
            item('s3', { ruleKeys: ['r:c'] }),
          ],
          [
            cand('c1', { ruleKey: 'r:a' }),
            cand('c2', { ruleKey: 'r:b' }),
            cand('c3', { ruleKey: 'r:c' }),
          ],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'c3', s3: null });
    });

    it('does not apply with more candidates than items', () => {
      expect(pairs([item('s1'), item('s2')], [cand('c1'), cand('c2'), cand('c3')])).toEqual({
        s1: 'ambiguous',
        s2: 'ambiguous',
      });
    });

    it('does not apply to open items alone', () => {
      expect(
        pairs(
          [item('o1', { status: 'open' }), item('o2', { status: 'open' })],
          [cand('c1'), cand('c2')],
        ),
      ).toEqual({ o1: 'ambiguous', o2: 'ambiguous' });
    });

    it('pairs by line hash at one distance in pass 2', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [item('s1', { line: 5, sonarLineHash: h }), item('s2', { line: 5, sonarLineHash: h })],
          [cand('c2', { line: 9, sonarLineHash: h }), cand('c1', { line: 9, sonarLineHash: h })],
        ),
      ).toEqual({ s1: 'c1', s2: 'c2' });
    });

    it('pairs items of mixed hash evidence that each reach every candidate', () => {
      const h = 'a'.repeat(32);
      // a (known hash) and b (unknown) are different groups; both reach ca (#h) and cb (unknown).
      const items = [item('a', { sonarLineHash: h }), item('b')];
      const cands = [cand('ca', { sonarLineHash: h }), cand('cb')];
      expect(byRef(items, cands)['a']).toMatchObject({ pass: 1, ambiguous: false });
      expect(pairs(items, cands)).toEqual({ a: 'ca', b: 'cb' });
      const rnd = prng(5);
      for (let run = 0; run < 10; run++) {
        expect(pairs(shuffle(items, rnd), shuffle(cands, rnd))).toEqual({ a: 'ca', b: 'cb' });
      }
    });

    it('does not apply when mixed hash evidence keeps an item from a candidate', () => {
      const h = 'a'.repeat(32);
      // a reaches ca and cc, not cb (#g); b reaches all three: more candidates than items (S5).
      expect(
        pairs(
          [item('a', { sonarLineHash: h }), item('b')],
          [
            cand('ca', { sonarLineHash: h }),
            cand('cb', { sonarLineHash: 'b'.repeat(32) }),
            cand('cc'),
          ],
        ),
      ).toEqual({ a: 'ambiguous', b: 'ambiguous' });
    });

    it('pairs by message at one distance in pass 3, the items on different lines', () => {
      const items = [
        item('s1', { line: 10, message: 'm', ruleKeys: ['r:x'] }),
        item('s2', { line: 20, message: 'm', ruleKeys: ['r:x'] }),
      ];
      const cands = [
        cand('c2', { line: 15, ruleKey: 'r:x' }),
        cand('c1', { line: 15, ruleKey: 'r:x' }),
      ];
      const r = byRef(items, cands);
      expect(r['s1']).toMatchObject({ candidateId: 'c1', pass: 3, ambiguous: false });
      expect(r['s2']).toMatchObject({ candidateId: 'c2', pass: 3, ambiguous: false });
    });
  });

  describe('twins with different comments (rulings S8, S8b, S8c)', () => {
    const twins = (a: string | null | undefined, b: string | null | undefined) =>
      pairs(
        [
          item('a', { message: 'm', ...(a !== undefined && { commentKey: a }) }),
          item('b', { message: 'm', ...(b !== undefined && { commentKey: b }) }),
        ],
        [cand('ca'), cand('cb')],
      );

    it('pair fully when their comments are the same, null with null', () => {
      expect(twins('safe here', 'safe here')).toEqual({ a: 'ca', b: 'cb' });
      expect(twins(null, null)).toEqual({ a: 'ca', b: 'cb' });
      expect(twins(null, undefined)).toEqual({ a: 'ca', b: 'cb' });
    });

    it('decide each for itself (S5) when their comments differ', () => {
      expect(twins('a is unused', 'b is needed')).toEqual({ a: 'ambiguous', b: 'ambiguous' });
      expect(twins('safe here', null)).toEqual({ a: 'ambiguous', b: 'ambiguous' });
      expect(twins('safe here', 'safe here ')).toEqual({ a: 'ambiguous', b: 'ambiguous' });
    });

    it('still pair an item whose one candidate is its own when comments differ (S5)', () => {
      expect(
        pairs(
          [
            item('s1', { ruleKeys: ['r:a', 'r:b'], commentKey: 'x' }),
            item('s2', { ruleKeys: ['r:b'], commentKey: 'y' }),
          ],
          [cand('c1', { ruleKey: 'r:a' }), cand('c2', { ruleKey: 'r:b' })],
        ),
      ).toEqual({ s1: 'c1', s2: 'c2' });
    });

    it('fall back to S5 in pass 3 too', () => {
      expect(
        pairs(
          [
            item('s1', { line: 10, message: 'm', ruleKeys: ['r:x'], commentKey: 'x' }),
            item('s2', { line: 10, message: 'm', ruleKeys: ['r:x'], commentKey: 'y' }),
          ],
          [cand('c1', { line: 15, ruleKey: 'r:x' }), cand('c2', { line: 15, ruleKey: 'r:x' })],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    describe('tied on one candidate (ruling S8b)', () => {
      it('are ambiguous when their comments differ, and the candidate is held back', () => {
        // Both reach only c1 in pass 1 (c2 is on another line, where pass 3 would reach it).
        const items = [
          item('a', { commentKey: 'x', message: 'm' }),
          item('b', { commentKey: 'y', message: 'm' }),
        ];
        const r = byRef(items, [cand('c1'), cand('c2', { line: 12 })]);
        expect(r['a']).toMatchObject({ candidateId: null, ambiguous: true });
        expect(r['b']).toMatchObject({ candidateId: null, ambiguous: true });
        expect(pairs(items, [cand('c1')])).toEqual({ a: 'ambiguous', b: 'ambiguous' });
      });

      it('pair the first in content order when their comments are the same', () => {
        expect(
          pairs([item('a', { commentKey: 'x' }), item('b', { commentKey: 'x' })], [cand('c1')]),
        ).toEqual({ a: 'c1', b: null });
      });

      it('are ambiguous across groups of different evidence tied on one candidate', () => {
        // s2 (known hash) and s3 (unknown) are different groups; each has c3 as its only one.
        const h = 'a'.repeat(32);
        const items = (s3: string) => [
          item('s1', { ruleKeys: ['r:a', 'r:b', 'r:c'], commentKey: 'x' }),
          item('s2', { ruleKeys: ['r:c'], sonarLineHash: h, commentKey: 'x' }),
          item('s3', { ruleKeys: ['r:c'], commentKey: s3 }),
        ];
        const cands = [
          cand('c1', { ruleKey: 'r:a' }),
          cand('c2', { ruleKey: 'r:b' }),
          cand('c3', { ruleKey: 'r:c' }),
        ];
        expect(pairs(items('y'), cands)).toEqual({
          s1: 'ambiguous',
          s2: 'ambiguous',
          s3: 'ambiguous',
        });
        expect(pairs(items('x'), cands)).toEqual({ s1: 'ambiguous', s2: 'c3', s3: null });
      });
    });
  });

  describe("the matcher's view of a request item (shared by the server and the fixture check)", () => {
    it('cleans a comment as the server stores it', () => {
      expect(sanitizeImportComment('  a\r\nb\rc\u0085d\u007fe\tf\u0000  ')).toBe('a\nb\ncde\tf');
    });

    it('keeps the evidence, the status and the marker, and compares the comment by its key', () => {
      const comment = importCommentHeader({
        key: 'AYi-1',
        label: 'False positive',
        date: '2026-09-10',
      });
      const a = statusMatchItem({
        ref: 'AYi-1',
        ruleKeys: ['eslint:eqeqeq'],
        path: 'src/a.ts',
        line: 2,
        sonarLineHash: null,
        message: 'm',
        status: 'false_positive',
        comment: `${comment}: safe\r\n`,
        competitorsUnknown: true,
      });
      expect(a).toEqual({
        ref: 'AYi-1',
        ruleKeys: ['eslint:eqeqeq'],
        path: 'src/a.ts',
        line: 2,
        sonarLineHash: null,
        message: 'm',
        status: 'false_positive',
        competitorsUnknown: true,
        commentKey: importCommentKey(`${comment}: safe`),
      });
      const open = statusMatchItem({
        ref: 'AYo-1',
        ruleKeys: ['eslint:eqeqeq'],
        path: 'src/a.ts',
        line: 2,
        sonarLineHash: null,
        message: 'm',
        status: 'open',
        comment: 'ignored',
      });
      expect(open).toMatchObject({ status: 'open', competitorsUnknown: false, commentKey: null });
    });
  });

  describe('the changelog comment (spec §10.2, ruling S8c)', () => {
    type Label = (typeof IMPORT_COMMENT_LABELS)[number];
    const at = (key: string, label: Label, date: string | null) =>
      importCommentHeader({ key, label, date });

    it('builds the header of spec §10.2', () => {
      expect(at('AYi-1', 'False positive', '2026-09-10')).toBe(
        'Imported from SonarQube issue AYi-1 (False positive on 2026-09-10)',
      );
      expect(at('AYi-3', "Won't fix", null)).toBe(
        "Imported from SonarQube issue AYi-3 (Won't fix)",
      );
      expect(IMPORT_COMMENT_LABELS).toEqual(['False positive', "Won't fix", 'Accepted']);
    });

    it('round-trips: only the key and the date are masked', () => {
      for (const label of IMPORT_COMMENT_LABELS) {
        for (const tail of ['', ': safe here', ': a\nb: c (x)']) {
          const one = importCommentKey(`${at('AYi-1', label, '2026-09-10')}${tail}`);
          expect(one).toBe(importCommentKey(`${at('AX_z.9:k-2', label, '2025-01-02')}${tail}`));
          expect(one).not.toBe(importCommentKey(`${at('AYi-1', label, null)}${tail}`));
          expect(one).not.toBe(importCommentKey(`${at('AYi-1', label, '2026-09-10')}${tail}!`));
        }
      }
    });

    it("keeps the status label: Accepted and Won't fix twins differ", () => {
      expect(importCommentKey(`${at('A', 'Accepted', '2026-09-10')}: x`)).not.toBe(
        importCommentKey(`${at('A', "Won't fix", '2026-09-10')}: x`),
      );
    });

    it('takes any other comment whole, never equal to a header form', () => {
      expect(importCommentKey('set by hand')).toBe(importCommentKey('set by hand'));
      expect(importCommentKey('set by hand')).not.toBe(importCommentKey('set by hand.'));
      const masked = importCommentKey(`${at('AYi-1', 'Accepted', '2026-09-10')}: x`);
      expect(importCommentKey(masked)).not.toBe(masked);
      expect(importCommentKey('Imported from SonarQube issue AYi-1 (Maybe): x')).not.toBe(
        importCommentKey('Imported from SonarQube issue AYi-2 (Maybe): x'),
      );
    });

    it('masks only a YYYY-MM-DD date: any other text in its place counts whole', () => {
      expect(
        importCommentKey(
          'Imported from SonarQube issue AYi-1 (False positive on verified safe): x',
        ),
      ).not.toBe(
        importCommentKey('Imported from SonarQube issue AYi-1 (False positive on NOT reviewed): x'),
      );
      expect(importCommentKey(`${at('AYi-1', 'False positive', 'verified safe')}: x`)).toMatch(
        /^raw:/,
      );
      expect(importCommentKey(`${at('AYi-1', 'False positive', '2026-9-10')}: x`)).toMatch(/^raw:/);
      expect(importCommentKey(`${at('AYi-1', 'False positive', '2026-09-10')}: x`)).toMatch(
        /^head:/,
      );
    });

    it('does not mask a key the header form cannot hold: such twins differ', () => {
      expect(importCommentKey(`${at('bad key', 'Accepted', null)}: x`)).not.toBe(
        importCommentKey(`${at('bad kez', 'Accepted', null)}: x`),
      );
    });
  });

  describe('open competitors (ruling S3)', () => {
    it('make a component asking false_positive and open ambiguous', () => {
      expect(pairs([item('fp'), item('o', { status: 'open' })], [cand('c1'), cand('c2')])).toEqual({
        fp: 'ambiguous',
        o: 'ambiguous',
      });
    });

    it('take their own candidate first, leaving the other one to the resolved item', () => {
      // o matches c1 by its message in pass 0; fp then has c2 alone on its line in pass 1.
      const r = byRef(
        [item('fp'), item('o', { status: 'open', message: 'mine' })],
        [cand('c1', { message: 'mine' }), cand('c2', { message: 'other' })],
      );
      expect(r['o']).toMatchObject({ candidateId: 'c1', pass: 0, ambiguous: false });
      expect(r['fp']).toMatchObject({ candidateId: 'c2', pass: 1, ambiguous: false });
    });

    it('contest a candidate the resolved item would reach at another distance', () => {
      const h = 'a'.repeat(32);
      expect(
        pairs(
          [
            item('o', { line: 11, sonarLineHash: h, status: 'open' }),
            item('fp', { line: 20, sonarLineHash: h }),
          ],
          [cand('c1', { line: 12, sonarLineHash: h })],
        ),
      ).toEqual({ o: 'ambiguous', fp: 'ambiguous' });
    });

    it('compete like any item when marked competitorsUnknown (the caller never applies them)', () => {
      expect(byRef([item('s1', { competitorsUnknown: true })], [cand('c1')])['s1']).toMatchObject({
        candidateId: 'c1',
        ambiguous: false,
      });
      expect(
        pairs(
          [item('s1', { competitorsUnknown: true }), item('s2', { status: 'wont_fix' })],
          [cand('c1')],
        ),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });
  });

  describe('a primary and its duplicate (§10.5)', () => {
    const cands = [cand('p', { line: 10 }), cand('d', { line: 20, duplicateOf: 'p' })];

    it('are both ambiguous when paired to different statuses', () => {
      expect(
        pairs([item('s1', { line: 10 }), item('s2', { line: 20, status: 'wont_fix' })], cands),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
      expect(
        pairs([item('s1', { line: 10 }), item('s2', { line: 20, status: 'open' })], cands),
      ).toEqual({ s1: 'ambiguous', s2: 'ambiguous' });
    });

    it('pair normally when asking the same status', () => {
      expect(pairs([item('s1', { line: 10 }), item('s2', { line: 20 })], cands)).toEqual({
        s1: 'p',
        s2: 'd',
      });
    });

    it('never mirrors a status onto a duplicate that was held back (I-1)', () => {
      // p and its duplicate d on one line; X and the open O both reach d, so d is held back, and
      // applying Y to p would mirror Y's status onto d, which O says is still open.
      const p = cand('p', { ruleKey: 'spotbugs:ES', line: 10 });
      const d = cand('d', { ruleKey: 'pmd:Use', line: 10, duplicateOf: 'p' });
      const y = item('Y', { ruleKeys: ['spotbugs:ES'] });
      const x = item('X', { ruleKeys: ['pmd:Use'] });
      const o = item('O', { ruleKeys: ['pmd:Use'], status: 'open' });
      expect(pairs([y, x, o], [p, d])).toEqual({ Y: 'ambiguous', X: 'ambiguous', O: 'ambiguous' });
      // Order does not matter.
      expect(pairs([o, x, y], [d, p])).toEqual({ Y: 'ambiguous', X: 'ambiguous', O: 'ambiguous' });
      // Without the open competitor, X and Y pair and both apply (same status).
      expect(pairs([y, x], [p, d])).toEqual({ Y: 'p', X: 'd' });
    });

    it('never mirrors onto a duplicate paired to an open or a competitorsUnknown item (I-1)', () => {
      const p = cand('p', { ruleKey: 'r:a', line: 10 });
      const d = cand('d', { ruleKey: 'r:b', line: 20, duplicateOf: 'p' });
      const y = item('Y', { ruleKeys: ['r:a'], line: 10 });
      expect(
        pairs([y, item('O', { ruleKeys: ['r:b'], line: 20, status: 'open' })], [p, d]),
      ).toEqual({ Y: 'ambiguous', O: 'ambiguous' });
      const r = byRef(
        [y, item('U', { ruleKeys: ['r:b'], line: 20, competitorsUnknown: true })],
        [p, d],
      );
      expect(r['Y']?.candidateId === null || r['Y']?.competitorsUnknown === true).toBe(true);
    });

    it('spreads until nothing changes: an item unpaired by the rule holds its candidate back too (I-1)', () => {
      // d is held back, so Y (on p) is ambiguous; p is then held back, so Z on p's other
      // duplicate d2 is ambiguous as well.
      const p = cand('p', { ruleKey: 'r:a', line: 10 });
      const d = cand('d', { ruleKey: 'r:b', line: 20, duplicateOf: 'p' });
      const d2 = cand('d2', { ruleKey: 'r:c', line: 30, duplicateOf: 'p' });
      const items = [
        item('Y', { ruleKeys: ['r:a'], line: 10 }),
        item('X', { ruleKeys: ['r:b'], line: 20 }),
        item('O', { ruleKeys: ['r:b'], line: 20, status: 'open' }),
        item('Z', { ruleKeys: ['r:c'], line: 30 }),
        item('W', { ruleKeys: ['r:w'], line: 40 }),
      ];
      const cands = [p, d, d2, cand('w', { ruleKey: 'r:w', line: 40 })];
      expect(pairs(items, cands)).toEqual({
        Y: 'ambiguous',
        X: 'ambiguous',
        O: 'ambiguous',
        Z: 'ambiguous',
        W: 'w',
      });
      const rnd = prng(7);
      for (let n = 0; n < 20; n++) {
        expect(pairs(shuffle(items, rnd), shuffle(cands, rnd))).toEqual(pairs(items, cands));
      }
    });
  });

  describe('competitorsUnknown reaches the whole component (ruling S12)', () => {
    // A -> {x, y}, B -> {y, z}; the rule of z was not read in full, so B is marked. A pairs with
    // cx on its own line, B with cz, but a missing competitor of z could push B onto cy, next to
    // A: nothing of the component is trusted.
    const a = item('A', { ruleKeys: ['r:x', 'r:y'], line: 10 });
    const b = item('B', { ruleKeys: ['r:y', 'r:z'], line: 30, competitorsUnknown: true });
    const cx = cand('cx', { ruleKey: 'r:x', line: 10 });
    const cy = cand('cy', { ruleKey: 'r:y', line: 20 });
    const cz = cand('cz', { ruleKey: 'r:z', line: 30 });

    it('marks every item linked to a marked one through candidates it may reach', () => {
      const r = byRef([a, b], [cx, cy, cz]);
      expect(r['A']).toMatchObject({
        candidateId: 'cx',
        ambiguous: false,
        competitorsUnknown: true,
      });
      expect(r['B']).toMatchObject({ competitorsUnknown: true });
      const rnd = prng(12);
      for (let run = 0; run < 10; run++) {
        const s = matchStatuses(shuffle([a, b], rnd), shuffle([cx, cy, cz], rnd));
        expect(s.every((m) => m.competitorsUnknown)).toBe(true);
      }
    });

    it('marks transitively, through open competitors and through a primary and its duplicate', () => {
      const c = item('C', { ruleKeys: ['r:w', 'r:x'], line: 50 });
      const cw = cand('cw', { ruleKey: 'r:w', line: 50 });
      expect(byRef([a, b, c], [cx, cy, cz, cw])['C']).toMatchObject({
        candidateId: 'cw',
        competitorsUnknown: true,
      });
      const o = item('O', { ruleKeys: ['r:v', 'r:z'], line: 70, status: 'open' });
      const d = item('D', { ruleKeys: ['r:v'], line: 90 });
      const cv = cand('cv', { ruleKey: 'r:v', line: 90 });
      expect(byRef([b, o, d], [cz, cv])['D']).toMatchObject({ competitorsUnknown: true });
      const e = item('E', { ruleKeys: ['r:u'], path: 'src/e.ts', line: 1 });
      const cu = cand('cu', { ruleKey: 'r:u', path: 'src/e.ts', line: 1, duplicateOf: 'cz' });
      expect(byRef([b, e], [cz, cu])['E']).toMatchObject({
        candidateId: 'cu',
        competitorsUnknown: true,
      });
    });

    it('leaves an item alone that shares no candidate with a marked one', () => {
      const r = byRef([a, b], [cx, cz]);
      expect(r['A']).toMatchObject({ candidateId: 'cx', competitorsUnknown: false });
      expect(r['B']).toMatchObject({ candidateId: 'cz', competitorsUnknown: true });
      const other = byRef([a, item('F', { path: 'src/f.ts', ruleKeys: ['r:x'] })], [cx])['F'];
      expect(other).toMatchObject({ candidateId: null, competitorsUnknown: false });
    });
  });

  describe('bounds (ruling S4)', () => {
    it('refuses more items than a request may carry, open competitors included', () => {
      const many = Array.from({ length: STATUS_IMPORT_MAX_ITEMS }, (_, n) =>
        item(`s${n}`, { status: n % 2 === 0 ? 'open' : 'false_positive' }),
      );
      expect(() => matchStatuses(many, [])).not.toThrow();
      expect(() => matchStatuses([...many, item('one-more', { status: 'open' })], [])).toThrow(
        /more than 1000 items/,
      );
    });

    it('refuses more candidates than a request may select, and duplicate candidate ids', () => {
      const many = Array.from({ length: STATUS_IMPORT_MAX_CANDIDATES + 1 }, (_, n) =>
        cand(`c${n}`),
      );
      expect(() => matchStatuses([item('s1')], many)).toThrow(/more than 20000 candidates/);
      expect(() => matchStatuses([item('s1')], [cand('c1'), cand('c1')])).toThrow(
        /duplicate candidate/,
      );
    });

    /** Runs the matcher and checks it against a time and a heap budget. */
    const bounded = (items: StatusItem[], cands: StatusCandidate[]) => {
      const heapBefore = process.memoryUsage().heapUsed;
      const started = performance.now();
      const r = matchStatuses(items, cands);
      expect(performance.now() - started).toBeLessThan(budgetMs(1000));
      expect(process.memoryUsage().heapUsed - heapBefore).toBeLessThan(200 * 1024 * 1024);
      return r;
    };
    const h = 'a'.repeat(32);
    const shared = (n: number, over: Partial<StatusItem> = {}) =>
      item(`s${n}`, {
        ruleKeys: ['r:x'],
        path: 'min.js',
        line: 1,
        sonarLineHash: h,
        message: 'm',
        ...over,
      });
    const sharedCand = (n: number) =>
      cand(`c${String(n).padStart(6, '0')}`, {
        ruleKey: 'r:x',
        path: 'min.js',
        line: 1,
        sonarLineHash: h,
      });

    it('settles a shared (path, line, hash) of 1 000 items and 20 000 candidates in bounds', () => {
      const cands = Array.from({ length: 20_000 }, (_, n) => sharedCand(n));
      const same = bounded(
        Array.from({ length: 1000 }, (_, n) => shared(n)),
        cands,
      );
      expect(same.every((m) => m.ambiguous)).toBe(true);
      const mixed = bounded(
        Array.from({ length: 1000 }, (_, n) =>
          shared(n, { status: n % 2 === 0 ? 'false_positive' : 'wont_fix' }),
        ),
        cands,
      );
      expect(mixed.every((m) => m.ambiguous)).toBe(true);
      // Distinct targets per item: 1 000 groups on the same line.
      const targets = bounded(
        Array.from({ length: 1000 }, (_, n) => shared(n, { ruleKeys: ['r:x', `r:only${n}`] })),
        cands,
      );
      expect(targets.every((m) => m.ambiguous)).toBe(true);
    });

    it('settles repeated line content (pass 2) of 1 000 items and 20 000 candidates in bounds', () => {
      const items = Array.from({ length: 1000 }, (_, n) =>
        item(`s${n}`, { ruleKeys: ['r:x'], line: 2 * n + 1, sonarLineHash: h }),
      );
      const cands = Array.from({ length: 20_000 }, (_, n) =>
        cand(`c${n}`, { ruleKey: 'r:x', line: 2 * n, sonarLineHash: h }),
      );
      // Each item sits between two candidates (lines 0, 2, 4, …): one chain of 1 000 items and
      // 1 001 candidates.
      expect(bounded(items, cands).every((m) => m.ambiguous)).toBe(true);
      // Every other item gone: 500 items, each with one candidate right below it.
      const sparse = items.filter((_, n) => n % 2 === 0);
      const far = Array.from({ length: 20_000 }, (_, n) =>
        cand(`c${n}`, { ruleKey: 'r:x', line: n < 500 ? 4 * n + 2 : 5000 + n, sonarLineHash: h }),
      );
      const r = bounded(sparse, far);
      expect(r.every((m) => m.candidateId !== null && m.pass === 2)).toBe(true);
    });

    it('settles repeated messages (pass 3) of 1 000 items and 20 000 candidates in bounds', () => {
      // The line hashes differ, so only pass 3 pairs: every item reaches 41 candidates.
      const at = (line: number, over: Partial<StatusItem> = {}) =>
        item(`s${line}`, { ruleKeys: ['r:x'], line, sonarLineHash: h, message: 'm', ...over });
      const cands = Array.from({ length: 20_000 }, (_, n) =>
        cand(`c${n}`, { ruleKey: 'r:x', line: n + 1, sonarLineHash: 'b'.repeat(32) }),
      );
      const mixed = Array.from({ length: 1000 }, (_, n) =>
        at(3 * n + 5, { status: n % 2 === 0 ? 'false_positive' : 'wont_fix' }),
      );
      expect(bounded(mixed, cands).every((m) => m.ambiguous)).toBe(true);
      // One status, candidates on every other line: an item on a candidate's line pairs with
      // it, one between two candidates is ambiguous.
      const same = Array.from({ length: 1000 }, (_, n) => at(3 * n + 5));
      const odd = cands.map((c, n) => ({ ...c, line: 2 * n + 1 }));
      const r = bounded(same, odd);
      expect(r.filter((m) => m.pass === 3).length).toBe(500);
      expect(r.filter((m) => m.ambiguous).length).toBe(500);
    });
  });

  it('gives the same result for every order of a mixed request', () => {
    const h1 = '1'.repeat(32);
    const h2 = '2'.repeat(32);
    const items = [
      item('a', { line: 3 }),
      item('b', { line: 3, status: 'wont_fix' }),
      item('c', { line: 5, sonarLineHash: h1 }),
      item('d', { line: 7, sonarLineHash: h1 }),
      item('e', { line: 40, message: 'm' }),
      item('f', { line: 50, message: 'm', status: 'wont_fix' }),
      item('g', { path: 'src/b.ts', line: 1, message: 'm' }),
      item('h', { path: 'src/b.ts', line: 1, message: 'm' }),
      item('i', { path: null, line: null }),
      item('j', { line: 12, sonarLineHash: h2, message: 'x' }),
      item('k', { line: 80, message: 'm' }),
      item('l', { line: 80, message: 'm', ruleKeys: ['eslint:no-var', 'eslint:eqeqeq'] }),
    ];
    const cands = [
      cand('c01', { line: 3 }),
      cand('c02', { line: 3 }),
      cand('c03', { line: 9, sonarLineHash: h1 }),
      cand('c04', { line: 11, sonarLineHash: h1 }),
      cand('c05', { line: 45 }),
      cand('c06', { path: 'src/b.ts', line: 1 }),
      cand('c07', { path: 'src/b.ts', line: 1 }),
      cand('c08', { path: null, line: null }),
      cand('c09', { line: 30, sonarLineHash: h2, message: 'y' }),
      cand('c10', { line: 82, ruleKey: 'eslint:no-var' }),
      cand('c11', { line: 78 }),
    ];
    const expected = byRef(items, cands);
    expect(
      Object.fromEntries(
        Object.values(expected).map((m) => [m.ref, m.ambiguous ? 'ambiguous' : m.candidateId]),
      ),
    ).toEqual({
      a: 'ambiguous',
      b: 'ambiguous',
      c: 'c04', // d is nearer to c03 (2 lines), so c takes the next one
      d: 'c03',
      e: 'ambiguous',
      f: 'ambiguous',
      g: 'c06', // g and h reach c06 and c07 alike and ask one status (ruling S6)
      h: 'c07',
      i: 'c08',
      j: 'c09',
      k: 'c11',
      l: 'c10',
    });
    const rnd = prng(42);
    for (let run = 0; run < 200; run++) {
      const its = shuffle(items, rnd);
      const result = matchStatuses(its, shuffle(cands, rnd));
      expect(result.map((m) => m.ref)).toEqual(its.map((i) => i.ref));
      expect(Object.fromEntries(result.map((m) => [m.ref, m]))).toEqual(expected);
    }
  });

  it('refuses two items with the same ref', () => {
    expect(() => matchStatuses([item('s1'), item('s1')], [])).toThrow(/duplicate ref/);
  });

  it('stays fast on one crowded file (1 000 items, 20 000 candidates on one path)', () => {
    const hash = (n: number) => (n % 100).toString(16).padStart(32, '0');
    const items = Array.from({ length: 1000 }, (_, n) =>
      item(`s${n}`, { line: n * 20 + 7, sonarLineHash: hash(n), message: 'm' }),
    );
    const cands = Array.from({ length: 20_000 }, (_, n) =>
      cand(`c${n}`, { line: n + 1, sonarLineHash: hash(n + 3) }),
    );
    const started = performance.now();
    matchStatuses(items, cands);
    expect(performance.now() - started).toBeLessThan(budgetMs(2000));
  });
});
