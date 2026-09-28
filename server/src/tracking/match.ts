/** What the matcher needs from a finding or an existing issue (data-model.md §5.2). */
export interface Trackable {
  ruleKey: string;
  path: string | null;
  lineHash: string;
  contextHash: string;
  /** `start_line`; null for a file-less finding. */
  line: number | null;
  /**
   * `start_column`; null for a file-less finding. Never an identity signal on its own:
   * `lineHash` and `contextHash` ignore whitespace (report-format.md §7.3), so a re-indented line
   * keeps its hashes but not its columns. The matcher uses columns to order the items that share
   * one line, to align two such lines when their counts differ ({@link alignLine}), and as a
   * bounded hint that two nearby lines with the very same layout are the same code
   * ({@link LAYOUT_PENALTY}).
   */
  column: number | null;
  message: string;
  /** Whether this is a `closed` candidate. Always false for a finding. `matchFindings` tries
   *  every pass against the non-closed candidates before it ever considers a closed one (U5 fix
   *  round 2, #2 — a per-pair tie-break cannot do this when the closed and open candidates it
   *  must choose between are not simultaneously adjacent to the same finding). */
  closed: boolean;
}

const SEP = '\u001f';

/**
 * The passes of data-model.md §5.2, strongest evidence first, plus an extra pass 0 ahead of them
 * (ruling U5 fix round 2, #1): two distinct findings that fall on the same physical line (e.g.
 * two unused-variable warnings on one `let a, b;`) get an *identical* line/context hash, because
 * the hash is computed from the line's text, not a column — so without also requiring the
 * message to match, pass 1 would lump them into one bucket. Pass 0 tries the extra-strong "same
 * hashes and same message" signal first; anything it cannot separate (truly identical findings,
 * or ones whose message also changed) still falls through to passes 1–4.
 */
const PASSES: readonly ((t: Trackable) => string)[] = [
  (t) => `${t.lineHash}${SEP}${t.contextHash}${SEP}${t.message}`,
  (t) => `${t.lineHash}${SEP}${t.contextHash}`,
  (t) => t.lineHash,
  (t) => `${t.line ?? ''}${SEP}${t.message}`,
  (t) => t.contextHash,
];

/** Step 0 of data-model.md §5.2: rewrites a candidate's path through `scm.renames`. */
export function renamer(
  renames: readonly { from: string; to: string }[],
): (path: string | null) => string | null {
  const to = new Map(renames.map((r) => [r.from, r.to]));
  return (path) => (path === null ? null : (to.get(path) ?? path));
}

/** A minimal binary min-heap, generic over its own ordering. */
class Heap<P> {
  private readonly items: P[] = [];

  constructor(private readonly less: (a: P, b: P) => boolean) {}

  get size(): number {
    return this.items.length;
  }

  push(item: P): void {
    const items = this.items;
    items.push(item);
    let i = items.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (!this.less(items[i] as P, items[parent] as P)) break;
      [items[i], items[parent]] = [items[parent] as P, items[i] as P];
      i = parent;
    }
  }

  pop(): P | undefined {
    const items = this.items;
    const top = items[0];
    const last = items.pop();
    if (items.length > 0 && last) {
      items[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let smallest = i;
        if (l < items.length && this.less(items[l] as P, items[smallest] as P)) smallest = l;
        if (r < items.length && this.less(items[r] as P, items[smallest] as P)) smallest = r;
        if (smallest === i) break;
        [items[i], items[smallest]] = [items[smallest] as P, items[i] as P];
        i = smallest;
      }
    }
    return top;
  }
}

/** One finding or candidate inside a line group. */
interface Item {
  index: number;
  column: number;
  message: string;
  /** Everything else that could tell two same-column items apart, for a total, input-order-free
   *  sort (two items equal on all of it are indistinguishable, so their order cannot matter). */
  rest: string;
}

const compareStrings = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

const compareItems = (a: Item, b: Item): number =>
  a.column - b.column ||
  compareStrings(a.message, b.message) ||
  compareStrings(a.rest, b.rest) ||
  a.index - b.index;

/**
 * Bounds on {@link alignLine}'s work, for two paired lines with differing counts n and m. Real
 * code rarely has more than a handful of findings of one rule on one line; these only cap the
 * worst case (e.g. a minified file).
 * - A single item on the short side: the best of the other side's items, O(m).
 * - Up to `SHIFT_SEARCH_LIMIT` (n·m) with at least two items on each side: the alignment is
 *   tried at every candidate column shift, O((n·m)²) ≤ 4 096 steps for ≥ 2 paired items.
 * - Otherwise, while both lines hold at most `ALIGN_MAX_ITEMS` items: three alignments, at
 *   shift 0 and at the shifts that align the first items and the last items,
 *   O(3·n·m) ≤ 192·min(n, m) — at most 192 steps per item it pairs.
 * - Beyond that: positional (1st↔1st…), O(min(n, m)).
 * So every pairing costs at most a constant per item it pairs, and the whole matcher stays
 * O(n log n) (the sorts and the heap).
 */
const SHIFT_SEARCH_LIMIT = 64;
const ALIGN_MAX_ITEMS = 64;

/**
 * Pairs the items of two matched line groups, each sorted left to right, preserving their
 * relative order (so a re-indented line, whose columns all moved, still pairs 1st↔1st,
 * 2nd↔2nd…). Always pairs `min(|f|, |c|)` items. With equal counts that is simply positional.
 * With differing counts (a finding appeared or disappeared on the line) it picks which items
 * of the longer side to leave over by an order-preserving alignment that minimises, in order:
 * the number of pairs whose message differs, then Σ|Δcolumn − s| for the best uniform column
 * shift `s` (so an unchanged line — `s` = 0 — or a uniformly re-indented one aligns exactly),
 * then |s|, then the negative s — within the bounds of {@link SHIFT_SEARCH_LIMIT}. The caller handles equal counts and
 * lines beyond {@link ALIGN_MAX_ITEMS} positionally. Returns `[findingPosition,
 * candidatePosition]` pairs.
 */
function alignLine(f: readonly Item[], c: readonly Item[]): [number, number][] {
  // `a` is the shorter side, every one of its items is paired; `b` has `b.length - k` left over.
  const findingsShorter = f.length < c.length;
  const a = findingsShorter ? f : c;
  const b = findingsShorter ? c : f;
  const delta = (i: number, j: number): number =>
    findingsShorter
      ? (a[i] as Item).column - (b[j] as Item).column
      : (b[j] as Item).column - (a[i] as Item).column;
  if (a.length === 1) {
    // Every shift fits a single item exactly, so the shift search reduces to: the item of `b`
    // with the same message if any, then the smallest |Δcolumn|, then the negative Δcolumn (the
    // candidate to the finding's right, as the full search of fix round 4 chose), then the
    // leftmost. O(m).
    const ai = a[0] as Item;
    let bestJ = 0;
    let bestKey: [number, number, number] | null = null;
    for (let j = 0; j < b.length; j++) {
      const d = delta(0, j);
      const key: [number, number, number] = [
        ai.message === (b[j] as Item).message ? 0 : 1,
        Math.abs(d),
        d,
      ];
      if (
        !bestKey ||
        key[0] < bestKey[0] ||
        (key[0] === bestKey[0] &&
          (key[1] < bestKey[1] || (key[1] === bestKey[1] && key[2] < bestKey[2])))
      ) {
        bestKey = key;
        bestJ = j;
      }
    }
    return [findingsShorter ? [0, bestJ] : [bestJ, 0]];
  }
  const shifts = new Set<number>([0]);
  if (a.length * b.length <= SHIFT_SEARCH_LIMIT) {
    for (let i = 0; i < a.length; i++) for (let j = 0; j < b.length; j++) shifts.add(delta(i, j));
  } else {
    // Too many items for every shift: also try the shifts that align the first items and the
    // last items, so a uniformly re-indented line whose count changed away from either end still
    // aligns exactly. Three alignments, still O(n·m).
    shifts.add(delta(0, 0));
    shifts.add(delta(a.length - 1, b.length - 1));
  }
  const ordered = [...shifts].sort((x, y) => Math.abs(x) - Math.abs(y) || x - y);

  const n = a.length;
  const m = b.length;
  const width = m + 1;
  // mis/cost at [i * width + j]: the best alignment of a[0..i) into b[0..j); row 0 stays 0.
  const mis = new Int32Array((n + 1) * width);
  const cost = new Float64Array((n + 1) * width);
  const took = new Uint8Array((n + 1) * width);
  let best: { mismatches: number; cost: number; pairs: [number, number][] } | null = null;
  for (const s of ordered) {
    for (let i = 1; i <= n; i++) {
      const ai = a[i - 1] as Item;
      for (let j = i; j <= m; j++) {
        const at = i * width + j;
        const diag = at - width - 1;
        const takeMis = (mis[diag] as number) + (ai.message === (b[j - 1] as Item).message ? 0 : 1);
        const takeCost = (cost[diag] as number) + Math.abs(delta(i - 1, j - 1) - s);
        // Skipping b[j-1] is only possible while a[0..i) still fits into b[0..j-1).
        const skipMis = j > i ? (mis[at - 1] as number) : Infinity;
        const skipCost = j > i ? (cost[at - 1] as number) : Infinity;
        const skip = skipMis < takeMis || (skipMis === takeMis && skipCost <= takeCost);
        mis[at] = skip ? skipMis : takeMis;
        cost[at] = skip ? skipCost : takeCost;
        took[at] = skip ? 0 : 1;
      }
    }
    const mismatches = mis[n * width + m] as number;
    const total = cost[n * width + m] as number;
    if (
      best &&
      (best.mismatches < mismatches || (best.mismatches === mismatches && best.cost <= total))
    ) {
      continue;
    }
    const pairs: [number, number][] = [];
    for (let i = n, j = m; i > 0; j--) {
      if (took[i * width + j]) {
        pairs.push(findingsShorter ? [i - 1, j - 1] : [j - 1, i - 1]);
        i--;
      }
    }
    best = { mismatches, cost: total, pairs };
  }
  return best?.pairs ?? [];
}

/**
 * How many lines of extra distance a pair of line groups is charged when their layouts differ
 * (see {@link pairWithinBucket}). Two lines whose flagged items sit at exactly the same columns
 * with the same messages are more likely the same code than two that merely hash alike — hashes
 * ignore whitespace, so indentation is the only thing that tells `a();` inside a block from
 * `a();` outside it — but only as a tie-breaker between nearby lines: a candidate more than this
 * many lines further away never wins on layout alone, so a re-indented line still pairs with its
 * nearest counterpart rather than with some far-away line that happens to keep its old columns.
 */
const LAYOUT_PENALTY = 10;

interface Group {
  side: 0 | 1; // 0 = findings, 1 = candidates
  line: number;
  /** This line's items, sorted by {@link compareItems}; those before `head` are already paired. */
  items: Item[];
  head: number;
  /** The line's layout ({@link layoutsOf}); ignored once `inLayout` is false. */
  layout: string;
  prev: Group | null;
  next: Group | null;
  /** Neighbours among the groups with the same layout; null/unlinked once `inLayout` is false. */
  layoutPrev: Group | null;
  layoutNext: Group | null;
  inLayout: boolean;
  removed: boolean;
}

interface GroupPair {
  cost: number;
  left: Group;
  right: Group;
  /** Whether `left`/`right` were adjacent in the layout list (else in the all-groups list). */
  viaLayout: boolean;
}

/** Cheapest first; equal costs go to the pair further up the file (a total order on distinct
 *  pairs, so the result never depends on insertion order). */
const groupLess = (a: GroupPair, b: GroupPair): boolean =>
  a.cost !== b.cost
    ? a.cost < b.cost
    : a.left.line !== b.left.line
      ? a.left.line < b.left.line
      : a.right.line !== b.right.line
        ? a.right.line < b.right.line
        : a.left.side < b.left.side;

const pairCost = (left: Group, right: Group): number =>
  right.line -
  left.line +
  (left.inLayout && right.inLayout && left.layout === right.layout ? 0 : LAYOUT_PENALTY);

/**
 * Each line's layout: the columns and messages of all the given items on that line. The caller
 * passes all of a bucket's findings, and only the candidates of the current round — the non-closed
 * ones, then the closed ones — so a closed issue's stale position never changes the layout of a
 * live issue's line.
 */
function layoutsOf(
  indices: readonly number[],
  of: (i: number) => Trackable | undefined,
): Map<number, string> {
  const byLine = new Map<number, string[]>();
  for (const index of indices) {
    const t = of(index);
    const line = t?.line ?? 0;
    let parts = byLine.get(line);
    if (!parts) byLine.set(line, (parts = []));
    parts.push(`${t?.column ?? 0}${SEP}${t?.message ?? ''}`);
  }
  const layouts = new Map<number, string>();
  for (const [line, parts] of byLine) {
    // Any canonical order will do: the layout is only ever compared for equality.
    layouts.set(line, parts.sort().join(SEP + SEP));
  }
  return layouts;
}

function groupsOf(
  side: 0 | 1,
  indices: readonly number[],
  of: (i: number) => Trackable | undefined,
  layouts: ReadonlyMap<number, string>,
): Group[] {
  const byLine = new Map<number, Item[]>();
  for (const index of indices) {
    const t = of(index);
    const line = t?.line ?? 0;
    let items = byLine.get(line);
    if (!items) byLine.set(line, (items = []));
    items.push({
      index,
      column: t?.column ?? 0,
      message: t?.message ?? '',
      rest: t ? `${t.lineHash}${SEP}${t.contextHash}` : '',
    });
  }
  return [...byLine].map(([line, items]) => {
    items.sort(compareItems);
    return {
      side,
      line,
      items,
      head: 0,
      layout: layouts.get(line) ?? '',
      prev: null,
      next: null,
      layoutPrev: null,
      layoutNext: null,
      inLayout: true,
      removed: false,
    };
  });
}

/**
 * Pairs one bucket's findings with its candidates (data-model.md §5.2, "ties"; U5 fix round 4).
 *
 * Items are grouped by line on each side, and line groups are paired greedily, cheapest first,
 * where a pair costs its |Δline| plus {@link LAYOUT_PENALTY} unless both lines have exactly the
 * same layout; equal costs go to the pair further up the file. Within a pair of line groups the
 * items are aligned by their left-to-right order ({@link alignLine}) — never by absolute column,
 * which a re-indent changes without changing any hash. A group with items left over (its line
 * had more findings, or more candidates, than its partner) stays in the sweep but loses its
 * layout bonus (what is left of the line no longer has the layout it was compared by), and goes
 * on to pair with its next-cheapest opposite group; so the sweep only stops once one side is
 * empty, and nothing matchable is ever stranded.
 *
 * The greedy runs in O(g log g) for g groups, plus the pairing work, which is at most a constant
 * per paired item: a positional pairing only advances each group's `head`, and the alignment
 * path only runs on lines of at most {@link ALIGN_MAX_ITEMS} items. In one dimension the closest
 * opposite-side pair of a set is always adjacent in line order, so the cheapest pair is always
 * adjacent either in the
 * list of all groups or in the list of the groups sharing its layout; both lists are linked
 * lists feeding one heap, and a popped pair whose cost has since grown (a group lost its layout)
 * is pushed back at its new cost. Deterministic whatever order the candidates arrive in: groups
 * are keyed by line, items sorted by content, and indices only break ties between identical
 * items.
 */
function pairWithinBucket(
  findings: readonly number[],
  candidates: readonly number[],
  findingOf: (i: number) => Trackable | undefined,
  candidateOf: (i: number) => Trackable | undefined,
  layouts: { findings: ReadonlyMap<number, string>; candidates: ReadonlyMap<number, string> },
  onPair: (finding: number, candidate: number) => void,
): void {
  const groups = [
    ...groupsOf(0, findings, findingOf, layouts.findings),
    ...groupsOf(1, candidates, candidateOf, layouts.candidates),
  ];
  groups.sort((x, y) => x.line - y.line || x.side - y.side);
  const lastByLayout = new Map<string, Group>();
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i] as Group;
    group.prev = groups[i - 1] ?? null;
    group.next = groups[i + 1] ?? null;
    const last = lastByLayout.get(group.layout);
    if (last) {
      last.layoutNext = group;
      group.layoutPrev = last;
    }
    lastByLayout.set(group.layout, group);
  }
  const heap = new Heap<GroupPair>(groupLess);
  const consider = (left: Group | null, right: Group | null, viaLayout: boolean): void => {
    if (!left || !right || left.side === right.side) return;
    heap.push({ cost: pairCost(left, right), left, right, viaLayout });
  };
  for (const group of groups) {
    consider(group, group.next, false);
    consider(group, group.layoutNext, true);
  }
  const leaveLayout = (group: Group): void => {
    if (!group.inLayout) return;
    group.inLayout = false;
    const { layoutPrev: before, layoutNext: after } = group;
    if (before) before.layoutNext = after;
    if (after) after.layoutPrev = before;
    consider(before, after, true);
  };
  while (heap.size > 0) {
    const pair = heap.pop();
    if (!pair) break;
    const { left, right, viaLayout } = pair;
    if (left.removed || right.removed) continue;
    if (viaLayout ? !left.inLayout || left.layoutNext !== right : left.next !== right) continue;
    const cost = pairCost(left, right);
    if (cost !== pair.cost) {
      heap.push({ ...pair, cost });
      continue;
    }
    const f = left.side === 0 ? left : right;
    const c = left.side === 0 ? right : left;
    const fCount = f.items.length - f.head;
    const cCount = c.items.length - c.head;
    if (fCount === cCount || Math.max(fCount, cCount) > ALIGN_MAX_ITEMS) {
      // Positional: pairs the first min(fCount, cCount) of each, so only a head moves — O(pairs).
      const k = Math.min(fCount, cCount);
      for (let i = 0; i < k; i++) {
        onPair((f.items[f.head + i] as Item).index, (c.items[c.head + i] as Item).index);
      }
      f.head += k;
      c.head += k;
    } else {
      // Both lines hold at most ALIGN_MAX_ITEMS items here, so compacting them is bounded too.
      const fItems = f.items.slice(f.head);
      const cItems = c.items.slice(c.head);
      const usedF = new Set<number>();
      const usedC = new Set<number>();
      for (const [fi, ci] of alignLine(fItems, cItems)) {
        usedF.add(fi);
        usedC.add(ci);
        onPair((fItems[fi] as Item).index, (cItems[ci] as Item).index);
      }
      f.items = fItems.filter((_, i) => !usedF.has(i));
      c.items = cItems.filter((_, i) => !usedC.has(i));
      f.head = 0;
      c.head = 0;
    }
    for (const group of [left, right]) {
      leaveLayout(group);
      if (group.items.length > group.head) continue;
      group.removed = true;
      const { prev: before, next: after } = group;
      if (before) before.next = after;
      if (after) after.prev = before;
      consider(before, after, false);
    }
  }
}

/**
 * data-model.md §5.2 step 1: matches findings to candidate issues in five passes (see
 * {@link PASSES}); every pass only pairs items with the same rule key and path that are still
 * unmatched, and — within a pass — tries every non-closed candidate before it tries any closed
 * one (`Trackable.closed`'s doc comment). Candidate paths must already be rewritten through the
 * renames (see {@link renamer}). Returns candidate index by finding index.
 */
export function matchFindings(
  findings: readonly Trackable[],
  candidates: readonly Trackable[],
): Map<number, number> {
  const matched = new Map<number, number>();
  const taken = new Set<number>();
  const findingOf = (i: number): Trackable | undefined => findings[i];
  const candidateOf = (i: number): Trackable | undefined => candidates[i];
  const onPair = (f: number, c: number): void => {
    matched.set(f, c);
    taken.add(c);
  };
  for (const passKey of PASSES) {
    const buckets = new Map<string, { findings: number[]; candidates: number[] }>();
    const keyOf = (t: Trackable): string => `${t.ruleKey}${SEP}${t.path ?? ''}${SEP}${passKey(t)}`;
    findings.forEach((f, i) => {
      if (matched.has(i)) return;
      const key = keyOf(f);
      let b = buckets.get(key);
      if (!b) buckets.set(key, (b = { findings: [], candidates: [] }));
      b.findings.push(i);
    });
    candidates.forEach((c, i) => {
      if (!taken.has(i)) buckets.get(keyOf(c))?.candidates.push(i);
    });
    for (const b of buckets.values()) {
      if (b.candidates.length === 0) continue;
      const findingLayouts = layoutsOf(b.findings, findingOf);
      const nonClosed = b.candidates.filter((c) => !candidates[c]?.closed);
      const closedCandidates = b.candidates.filter((c) => candidates[c]?.closed);
      if (nonClosed.length > 0) {
        const layouts = { findings: findingLayouts, candidates: layoutsOf(nonClosed, candidateOf) };
        pairWithinBucket(b.findings, nonClosed, findingOf, candidateOf, layouts, onPair);
      }
      const stillUnmatched = b.findings.filter((f) => !matched.has(f));
      if (closedCandidates.length > 0 && stillUnmatched.length > 0) {
        const layouts = {
          findings: findingLayouts,
          candidates: layoutsOf(closedCandidates, candidateOf),
        };
        pairWithinBucket(stillUnmatched, closedCandidates, findingOf, candidateOf, layouts, onPair);
      }
    }
  }
  return matched;
}
