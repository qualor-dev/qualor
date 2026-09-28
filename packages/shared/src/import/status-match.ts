export const IMPORT_STATUSES = ['false_positive', 'wont_fix'] as const;
export type ImportStatus = (typeof IMPORT_STATUSES)[number];
/**
 * The status of a matching item (spec §10.1): resolved in SonarQube, or `open`, an open SonarQube
 * issue sent only as a competitor. An `open` item takes part in the matching and is never applied.
 */
export type StatusItemStatus = ImportStatus | 'open';

export const STATUS_IMPORT_OUTCOMES = [
  'applied',
  'would_apply',
  'already_set',
  'conflict',
  'unmatched',
  'ambiguous',
  'competitors_unknown',
] as const;
export type StatusImportOutcome = (typeof STATUS_IMPORT_OUTCOMES)[number];

/** Spec §11.2: at most this many items per request, `open` competitors included. */
export const STATUS_IMPORT_MAX_ITEMS = 1000;
/** Spec §11.2: at most this many candidate issues per request (more is 413 IMPORT_TOO_LARGE). */
export const STATUS_IMPORT_MAX_CANDIDATES = 20_000;
/** Spec §10.4 pass 3: a message-only pair is at most this many lines apart. */
export const MESSAGE_PASS_MAX_LINES = 20;

export interface StatusItem {
  ref: string;
  ruleKeys: readonly string[];
  path: string | null;
  line: number | null;
  sonarLineHash: string | null;
  message: string | null;
  status: StatusItemStatus;
  /**
   * Spec §10.1: SonarQube's open issues of this item's rule could not all be read, so competitors
   * may be missing. The item still competes like any other; its caller reports it
   * `competitors_unknown` and never applies it.
   */
  competitorsUnknown?: boolean;
  /**
   * Rulings S8 and S8c: what the item's changelog comment says, as `importCommentKey` gives it
   * (the whole comment with only the SonarQube key and the date masked); `null` or absent for
   * none. Pairing an item with the candidate of a twin (a full pairing, ruling S6, or the first
   * of items tied on one candidate) gives that candidate the item's comment, so it needs the same
   * value on every item concerned.
   */
  commentKey?: string | null;
}

/** Spec §10.2: the status labels of the changelog comment's header. */
export const IMPORT_COMMENT_LABELS = ['False positive', "Won't fix", 'Accepted'] as const;
export type ImportCommentLabel = (typeof IMPORT_COMMENT_LABELS)[number];

/**
 * The changelog comment of spec §10.2: its header, then `: ` and the latest SonarQube comment, if
 * any. Groups: the SonarQube key, the label, ` on <date>`, the rest (empty, or `: ` and the
 * comment).
 */
const IMPORT_COMMENT_HEAD =
  /^Imported from SonarQube issue ([A-Za-z0-9_.:-]{1,100}) \((False positive|Won't fix|Accepted)( on \d{4}-\d{2}-\d{2})?\)((?:: [\s\S]*)?)$/;

/**
 * Spec §10.2: the header of the changelog comment, `Imported from SonarQube issue <key> (<label>
 * on <date>)`, or without ` on <date>` when `date` is `null`. The CLI builds every item's comment
 * with it (the header, then `: ` and the latest SonarQube comment when there is one), so that
 * `importCommentKey` can mask the key and the date. `date` must be a day, `YYYY-MM-DD` (the CLI
 * writes nothing else). A key outside `[A-Za-z0-9_.:-]{1,100}` or a date of any other form is
 * written as given but not masked (ruling 9c: free text there must never be masked away): the
 * comment then counts whole, and twins never compare equal by it.
 */
export function importCommentHeader(o: {
  key: string;
  label: ImportCommentLabel;
  date: string | null;
}): string {
  return `Imported from SonarQube issue ${o.key} (${o.label}${o.date === null ? '' : ` on ${o.date}`})`;
}

/**
 * Ruling S8c: what twins compare to tell whether one may take the other's candidate: the WHOLE
 * (sanitised) changelog comment with only the SonarQube key and the date masked. The status label,
 * whether a date is there, and every character of the rest count. A comment of any other form
 * counts whole; the two forms are kept apart, so neither can equal the other.
 */
export function importCommentKey(comment: string): string {
  const m = IMPORT_COMMENT_HEAD.exec(comment);
  if (m === null) return `raw:${comment}`;
  return `head:${JSON.stringify([m[2] ?? '', m[3] !== undefined, m[4] ?? ''])}`;
}

/** A resolved item as the endpoint receives it: with its changelog comment. */
export interface StatusImportItem extends StatusItem {
  status: ImportStatus;
  comment: string;
}

/** An open SonarQube issue, sent only as a competitor (spec §10.1): never applied, no comment. */
export interface StatusCompetitorItem extends Omit<StatusItem, 'status' | 'competitorsUnknown'> {
  status: 'open';
  comment?: string;
}

/** One item of `POST /projects/{id}/issue-status-import` (spec §11.2). */
export type StatusImportRequestItem = StatusImportItem | StatusCompetitorItem;

/** Every control character except the tab and the line feed. */
const COMMENT_CONTROL = /[^\P{Cc}\t\n]/gu;

/**
 * Spec §10.2, §11.2, a changelog comment as the server stores it: a CRLF or a lone CR
 * becomes a line feed, every other control character but the tab goes, and the result is
 * trimmed. It is never longer than the input.
 */
export function sanitizeImportComment(comment: string): string {
  return comment.replace(/\r\n?/g, '\n').replace(COMMENT_CONTROL, '').trim();
}

/**
 * Spec §10.4: the matcher's view of a request item, as the import endpoint builds it: everything
 * but its comment, which is compared as a whole once sanitised, with only the SonarQube key and
 * the date masked (rulings S8, S8b and S8c: an item never takes a twin's candidate when their
 * comments differ). Shared by the server and the fixture check, so that neither keeps a copy.
 */
export function statusMatchItem(i: StatusImportRequestItem): StatusItem {
  return {
    ref: i.ref,
    ruleKeys: i.ruleKeys,
    path: i.path,
    line: i.line,
    sonarLineHash: i.sonarLineHash,
    message: i.message,
    status: i.status,
    competitorsUnknown: i.status !== 'open' && i.competitorsUnknown === true,
    commentKey: i.status === 'open' ? null : importCommentKey(sanitizeImportComment(i.comment)),
  };
}

export interface StatusCandidate {
  id: string;
  ruleKey: string;
  path: string | null;
  line: number | null;
  sonarLineHash: string | null;
  message: string;
  /** The primary this issue is a duplicate of (data-model.md §5.3), if any. */
  duplicateOf?: string | null;
}

/**
 * One item's match. `candidateId` is also set for an `open` item and for an item whose
 * `competitorsUnknown` is set here: they consume their candidate, but a caller never applies them.
 */
export interface StatusMatch {
  ref: string;
  candidateId: string | null;
  pass: Pass | null;
  ambiguous: boolean;
  /**
   * Ruling S12: the item is marked `competitorsUnknown`, or is linked to one that is through the
   * candidates they may reach (see `matchStatuses`). Its caller reports it `competitors_unknown`
   * and applies nothing for it.
   */
  competitorsUnknown: boolean;
}

export interface StatusImportResult {
  ref: string;
  outcome: StatusImportOutcome;
  issueId: string | null;
  status: string | null;
}

type Pass = 0 | 1 | 2 | 3;

/** An item in content order, with its rule targets sorted and deduplicated. */
interface Entry {
  item: StatusItem;
  n: number;
  targets: readonly string[];
  hash: string | null;
  done: boolean;
}

/** Items of one pass with identical evidence (and status): they reach the same candidates. */
interface Group {
  entries: Entry[];
  status: StatusItemStatus;
  /** The group's node in the pass's union-find (after every candidate's). */
  node: number;
  /** Passes 0 and 1: the runs the group reaches. */
  runs: Run[];
}

/** Candidates (indices, ascending, i.e. by line then id) that one piece of evidence reaches. */
interface Run {
  cands: number[];
  /** Free candidates left (passes 2 and 3). */
  free: number;
  /** The level that last compacted this run. */
  stamp: number;
  /** Passes 2 and 3: the line of a bucket this run is. */
  slot: { bucket: LineBucket; index: number } | null;
  /** Passes 2 and 3: items of different statuses reach this run's candidates in the pass. */
  contested: boolean;
}

/** Passes 2 and 3: one rule's candidates of one (path, hash or message), by distinct line. */
interface LineBucket {
  lines: number[];
  runs: Run[];
  /** Next non-empty line index at or right of i (`i` itself when non-empty; `lines.length` = none). */
  right: Int32Array;
  /** The same to the left, shifted by one (`0` = none). */
  left: Int32Array;
}

/** A group's walk over one bucket, outwards from the group's line, nearest line first. */
interface Cursor {
  group: Group;
  bucket: LineBucket;
  line: number;
  /** The next line index to look at on each side. */
  r: number;
  l: number;
  /** The distance of the next line with free candidates. */
  d: number;
}

interface Component {
  groups: Group[];
  runs: Run[];
  statuses: Set<StatusItemStatus>;
  contested: boolean;
}

const cmp = (a: string | number, b: string | number) => (a < b ? -1 : a > b ? 1 : 0);
/** `null` (file-less, or no line) sorts first. */
const cmpNullable = <T extends string | number>(a: T | null, b: T | null) =>
  a === null ? (b === null ? 0 : -1) : b === null ? 1 : cmp(a, b);
/** Ruling S1: a line hash of `""` or `null` is unknown, and unknown never matches. */
const knownHash = (h: string | null): string | null => (h === null || h === '' ? null : h);
const key = (...parts: (string | number | null)[]) => JSON.stringify(parts);

/** Union-find over `0..size-1`: union by rank, full path compression, reset in O(touched). */
class UnionFind {
  private readonly parent: Int32Array;
  private readonly rank: Uint8Array;
  private readonly touched: number[] = [];

  constructor(size: number) {
    this.parent = Int32Array.from({ length: size }, (_, i) => i);
    this.rank = new Uint8Array(size);
  }

  find(a: number): number {
    let root = a;
    for (let p = this.parent[root] ?? root; p !== root; p = this.parent[root] ?? root) root = p;
    for (let x = a; x !== root;) {
      const next = this.parent[x] ?? root;
      this.parent[x] = root;
      x = next;
    }
    return root;
  }

  union(a: number, b: number): void {
    let x = this.find(a);
    let y = this.find(b);
    if (x === y) return;
    const rx = this.rank[x] ?? 0;
    const ry = this.rank[y] ?? 0;
    if (rx < ry) [x, y] = [y, x];
    this.parent[y] = x;
    this.touched.push(y);
    if (rx === ry) {
      this.rank[x] = rx + 1;
      this.touched.push(x);
    }
  }

  /** Every node back to a singleton. */
  reset(): void {
    for (const n of this.touched) {
      this.parent[n] = n;
      this.rank[n] = 0;
    }
    this.touched.length = 0;
  }
}

/** A binary min-heap of cursors by distance. */
class CursorHeap {
  private readonly heap: Cursor[] = [];

  get size(): number {
    return this.heap.length;
  }

  peek(): Cursor | undefined {
    return this.heap[0];
  }

  push(c: Cursor): void {
    const h = this.heap;
    h.push(c);
    for (let i = h.length - 1; i > 0;) {
      const up = (i - 1) >> 1;
      const parent = h[up];
      if (parent === undefined || parent.d <= c.d) break;
      h[i] = parent;
      h[up] = c;
      i = up;
    }
  }

  pop(): Cursor | undefined {
    const h = this.heap;
    const top = h[0];
    const last = h.pop();
    if (top === undefined || last === undefined || h.length === 0) return top;
    h[0] = last;
    for (let i = 0; ;) {
      const a = 2 * i + 1;
      const b = a + 1;
      let m = i;
      if ((h[a]?.d ?? Infinity) < (h[m]?.d ?? Infinity)) m = a;
      if ((h[b]?.d ?? Infinity) < (h[m]?.d ?? Infinity)) m = b;
      if (m === i) break;
      const t = h[m];
      if (t === undefined) break;
      h[m] = last;
      h[i] = t;
      i = m;
    }
    return top;
  }
}

/** The first index of the ascending `lines` whose value is at least `line`. */
function lowerBound(lines: readonly number[], line: number): number {
  let lo = 0;
  let hi = lines.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((lines[mid] ?? Infinity) < line) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function findRight(b: LineBucket, i: number): number {
  let root = i;
  for (let p = b.right[root] ?? root; p !== root; p = b.right[root] ?? root) root = p;
  for (let x = i; x !== root;) {
    const next = b.right[x] ?? root;
    b.right[x] = root;
    x = next;
  }
  return root;
}

function findLeft(b: LineBucket, i: number): number {
  let root = i + 1;
  for (let p = b.left[root] ?? root; p !== root; p = b.left[root] ?? root) root = p;
  for (let x = i + 1; x !== root;) {
    const next = b.left[x] ?? root;
    b.left[x] = root;
    x = next;
  }
  return root - 1;
}

/**
 * Spec §10.4. The result depends only on the content of items and candidates: items are ordered
 * by `(path, line, ref)` and candidates by `(line, id)` before anything is paired.
 *
 * Within a pass (and, in passes 2 and 3, within one line distance) the evidence of every pair is
 * equally strong. The items and candidates that compete there form connected components. A
 * component is `ambiguous` when its items ask for more than one status (`open` competitors
 * included): its items are left unpaired and its candidates are held back from the later, weaker
 * passes, since nothing tells which Qualor issue is which. In passes 2 and 3 a candidate that
 * items of different statuses reach at any distance is contested up front, with the same effect.
 * A component asking one resolved status, with no item marked `competitorsUnknown` and the same
 * comment on every item (rulings S8 and S8c), whose every
 * item reaches every candidate and whose items are at least as many as its candidates, pairs
 * fully (ruling S6): every candidate gets that status whatever the pairing, so items in content
 * order pair with candidates by (line, id). In any other component each item decides for itself
 * (rulings S2 and S5): from its free candidates at this level, those that are the only option
 * of some other item are removed (unless it has only that one itself); an item left with exactly
 * one pairs with it, any other item is ambiguous and its candidates are held back. Items left with
 * the same one candidate ask the same status: the first in content order pairs and the others
 * stay unpaired, when they all carry the same comment; else they are all ambiguous and the
 * candidate is held back (ruling S8b). Then a primary
 * and its duplicate paired to items of different statuses make both items ambiguous (§10.5), and
 * a resolved item paired to the primary or a duplicate of a candidate whose own counterpart is
 * unsure (held back, or paired to an `open` or `competitors_unknown` item) is ambiguous too, until
 * nothing changes (I-1, `holdMirroredDuplicates`).
 *
 * Last (ruling S12), `competitorsUnknown` spreads over the whole component, taken across every
 * pass: items are linked through every candidate they may reach in any pass (the same path and a
 * rule among their targets, whatever the line), candidates through a primary and its duplicate,
 * `open` competitors included. A missing competitor of a marked item may move that item, and so
 * any item linked to it, onto another candidate; so every item linked to a marked one is
 * `competitorsUnknown` too.
 *
 * Cost (ruling S4): items with identical evidence are one node, every run of candidates one
 * piece of evidence reaches is linked once per level, an item's candidates are looked at only
 * until a second one of its own shows up, and a line with no free candidate is skipped in
 * near-constant time; a request at the bounds takes well under a second.
 *
 * `ref`s and candidate ids must be unique (the endpoint refuses duplicate refs with 422).
 */
export function matchStatuses(
  items: readonly StatusItem[],
  candidates: readonly StatusCandidate[],
): StatusMatch[] {
  if (items.length > STATUS_IMPORT_MAX_ITEMS) {
    throw new Error(`matchStatuses: more than ${STATUS_IMPORT_MAX_ITEMS} items`);
  }
  if (candidates.length > STATUS_IMPORT_MAX_CANDIDATES) {
    throw new Error(`matchStatuses: more than ${STATUS_IMPORT_MAX_CANDIDATES} candidates`);
  }
  const refs = new Set<string>();
  for (const i of items) {
    if (refs.has(i.ref)) throw new Error(`matchStatuses: duplicate ref ${i.ref}`);
    refs.add(i.ref);
  }
  const cands = [...candidates].sort((a, b) => cmpNullable(a.line, b.line) || cmp(a.id, b.id));
  for (let k = 1; k < cands.length; k++) {
    if (cands[k]?.id === cands[k - 1]?.id) {
      throw new Error(`matchStatuses: duplicate candidate ${cands[k]?.id ?? ''}`);
    }
  }
  const C = cands.length;

  const order: Entry[] = [...items]
    .sort((a, b) => cmpNullable(a.path, b.path) || cmpNullable(a.line, b.line) || cmp(a.ref, b.ref))
    .map((item, n) => ({
      item,
      n,
      targets: [...new Set(item.ruleKeys)].sort(cmp),
      hash: knownHash(item.sonarLineHash),
      done: false,
    }));

  const result = new Map<string, Omit<StatusMatch, 'competitorsUnknown'>>();
  /** Candidates paired, or held back by an ambiguous component. */
  const taken = new Uint8Array(C);
  /** The level at which a candidate was last the only option of some group (ruling S5). */
  const forced = new Int32Array(C).fill(-1);
  /** Passes 2 and 3: the bucket line each candidate is in. */
  let runOf: (Run | undefined)[] = [];
  let level = 0;
  let pass: Pass = 0;

  const settleEntry = (e: Entry, candidate: number | null, ambiguous: boolean) => {
    e.done = true;
    const ref = e.item.ref;
    const c = candidate === null ? null : (cands[candidate] ?? null);
    result.set(ref, {
      ref,
      candidateId: c?.id ?? null,
      pass: c === null ? null : pass,
      ambiguous,
    });
  };
  const openEntries = (g: Group) => g.entries.filter((e) => !e.done);
  /** Rulings S8 and S8c: every entry carries the same comment (`null` equals absent). */
  const sameComment = (entries: readonly Entry[]): boolean =>
    entries.every((e) => (e.item.commentKey ?? null) === (entries[0]?.item.commentKey ?? null));
  const markAmbiguous = (g: Group) => {
    for (const e of openEntries(g)) settleEntry(e, null, true);
  };
  const take = (ci: number) => {
    if (taken[ci] === 1) return;
    taken[ci] = 1;
    const run = runOf[ci];
    if (run === undefined) return;
    run.free--;
    if (run.free === 0 && run.slot !== null) {
      const { bucket, index } = run.slot;
      bucket.right[index] = index + 1;
      bucket.left[index + 1] = index;
    }
  };
  const compact = (run: Run) => {
    if (run.cands.some((ci) => taken[ci] === 1))
      run.cands = run.cands.filter((ci) => taken[ci] !== 1);
  };
  /** Groups of the open items by `evidence`, in content order; `null` evidence skips the item. */
  const groupsOf = (evidence: (e: Entry) => string | null): Group[] => {
    const byKey = new Map<string, Group>();
    for (const e of order) {
      if (e.done) continue;
      const k = evidence(e);
      if (k === null) continue;
      const full = key(k, e.item.status, ...e.targets);
      const g = byKey.get(full);
      if (g) g.entries.push(e);
      else byKey.set(full, { entries: [e], status: e.item.status, node: 0, runs: [] });
    }
    const groups = [...byKey.values()];
    groups.forEach((g, k) => (g.node = C + k));
    return groups;
  };

  /** Settles one level of equally strong evidence: components, ambiguity, pairing. */
  const settle = (uf: UnionFind, reach: ReadonlyMap<Group, readonly Run[]>) => {
    level++;
    uf.reset();
    const visited: Run[] = [];
    const linked: Group[] = [];
    for (const [g, runs] of reach) {
      let any = false;
      for (const run of runs) {
        if (run.stamp !== level) {
          run.stamp = level;
          // A contested run is never paired nor taken during its pass: one node stands for it.
          if (!run.contested) compact(run);
          const first = run.cands[0];
          if (first === undefined) continue;
          visited.push(run);
          if (!run.contested) for (const ci of run.cands) uf.union(first, ci);
        }
        const first = run.cands[0];
        if (first === undefined) continue;
        uf.union(g.node, first);
        any = true;
      }
      if (any) linked.push(g);
    }
    const components = new Map<number, Component>();
    const componentOf = (node: number): Component => {
      const root = uf.find(node);
      let c = components.get(root);
      if (!c) {
        c = { groups: [], runs: [], statuses: new Set(), contested: false };
        components.set(root, c);
      }
      return c;
    };
    for (const g of linked) {
      const c = componentOf(g.node);
      c.groups.push(g);
      c.statuses.add(g.status);
    }
    for (const run of visited) {
      const c = componentOf(run.cands[0] ?? 0);
      if (run.contested) {
        c.contested = true;
        continue;
      }
      c.runs.push(run);
    }
    for (const c of components.values()) {
      if (c.contested || c.statuses.size > 1) {
        for (const g of c.groups) markAmbiguous(g);
        for (const run of c.runs) for (const ci of run.cands) take(ci);
        continue;
      }
      if (!pairFully(c, reach)) pairEachItem(c, reach);
    }
  };

  /**
   * Ruling S6: a component whose items all ask the same resolved status (no `open` competitor,
   * no item marked `competitorsUnknown`) and carry the same comment (rulings S8 and S8c:
   * `commentKey`, `null` equals `null`), whose every item reaches every one of its candidates,
   * with at least as many items as candidates. Every candidate then receives that status
   * whichever pairing is chosen, so the result does not depend on the pairing: items in content
   * order pair with candidates by (line, id), and the items left over stay unpaired. Which of the
   * twins' SonarQube keys (and dates) ends in which issue's changelog is arbitrary, and nothing
   * else is. Returns
   * `false`, pairing nothing, when the component does not qualify.
   */
  const pairFully = (c: Component, reach: ReadonlyMap<Group, readonly Run[]>): boolean => {
    const status = c.groups[0]?.status;
    if (status === undefined || status === 'open') return false;
    const entries: Entry[] = [];
    for (const g of c.groups) {
      for (const e of openEntries(g)) {
        if (e.item.competitorsUnknown === true) return false;
        entries.push(e);
      }
    }
    // Ruling S8: twins whose comments differ are not interchangeable.
    if (!sameComment(entries)) return false;
    // A group's runs are disjoint, so its size is the sum of their lengths.
    const sizes: number[] = [];
    for (const g of c.groups) {
      let size = 0;
      for (const run of reach.get(g) ?? []) size += run.cands.length;
      if (size > entries.length) return false;
      sizes.push(size);
    }
    // The component's runs may overlap (passes 0 and 1: a candidate is in its `*` run and in its
    // hash run), so its candidates are counted once each.
    const all = new Set<number>();
    for (const run of c.runs) for (const ci of run.cands) all.add(ci);
    if (all.size === 0 || all.size > entries.length) return false;
    // Every group reaching as many distinct candidates as the component has reaches all of them.
    if (sizes.some((s) => s !== all.size)) return false;
    entries.sort((a, b) => a.n - b.n);
    const ordered = [...all].sort((a, b) => a - b);
    ordered.forEach((ci, k) => {
      const e = entries[k];
      if (e === undefined) return;
      take(ci);
      settleEntry(e, ci, false);
    });
    return true;
  };

  /**
   * Rulings S2 and S5, in a component asking one status: every group (items of identical
   * evidence) keeps the candidates it reaches minus those that are the only option of another
   * group, and pairs only when exactly one is left; items left with the same one candidate pair
   * the first of them only when all carry the same comment (ruling S8b), else all are ambiguous
   * and the candidate is held back. Decided before anything is taken, so the
   * result does not depend on the order of the groups. A group's runs are disjoint (distinct
   * rules, hash classes or lines), so its size is the sum of their lengths.
   */
  const pairEachItem = (c: Component, reach: ReadonlyMap<Group, readonly Run[]>) => {
    const sizes = new Map<Group, number>();
    for (const g of c.groups) {
      let size = 0;
      let only = -1;
      for (const run of reach.get(g) ?? []) {
        size += run.cands.length;
        if (only === -1) only = run.cands[0] ?? -1;
      }
      sizes.set(g, size);
      if (size === 1 && only !== -1) forced[only] = level;
    }
    const held = new Set<Run>();
    const entries: { e: Entry; ci: number }[] = [];
    for (const g of c.groups) {
      const alone = sizes.get(g) === 1;
      let one = -1;
      let many = false;
      scan: for (const run of reach.get(g) ?? []) {
        for (const ci of run.cands) {
          if ((!alone && forced[ci] === level) || ci === one) continue;
          if (one !== -1) {
            many = true;
            break scan;
          }
          one = ci;
        }
      }
      if (one === -1 || many) {
        markAmbiguous(g);
        for (const run of reach.get(g) ?? []) held.add(run);
        continue;
      }
      for (const e of openEntries(g)) entries.push({ e, ci: one });
    }
    // Items left with the same one candidate ask the same status: the first by content pairs,
    // provided they say the same (ruling S8b); else none can be told from the others, so all are
    // ambiguous and the candidate is held back.
    entries.sort((a, b) => a.e.n - b.e.n);
    const tied = new Map<number, Entry[]>();
    for (const { e, ci } of entries) {
      const list = tied.get(ci);
      if (list) list.push(e);
      else tied.set(ci, [e]);
    }
    for (const [ci, list] of tied) {
      if (taken[ci] === 1) continue;
      take(ci);
      const [first] = list;
      if (first === undefined) continue;
      if (sameComment(list)) settleEntry(first, ci, false);
      else for (const e of list) settleEntry(e, null, true);
    }
    // An ambiguous item's candidates are held back after the pairs: one may be another's only one.
    for (const run of held) for (const ci of run.cands) take(ci);
  };

  // Passes 0 and 1: one level each, same line.
  for (const p of [0, 1] as const) {
    pass = p;
    runOf = [];
    const runs = new Map<string, Run>();
    const addTo = (k: string, ci: number) => {
      const run = runs.get(k);
      if (run) run.cands.push(ci);
      else runs.set(k, { cands: [ci], free: 1, stamp: -1, slot: null, contested: false });
    };
    cands.forEach((c, ci) => {
      if (taken[ci] === 1) return;
      const base = [c.path, c.line, c.ruleKey, p === 0 ? c.message : null];
      const h = knownHash(c.sonarLineHash);
      addTo(key(...base, '*'), ci);
      addTo(key(...base, h === null ? '?' : `#${h}`), ci);
    });
    const groups = groupsOf((e) =>
      p === 0 && e.item.message === null
        ? null
        : key(e.item.path, e.item.line, p === 0 ? e.item.message : null, e.hash),
    );
    const reach = new Map<Group, Run[]>();
    for (const g of groups) {
      const i = g.entries[0];
      if (i === undefined) continue;
      for (const t of i.targets) {
        const base = [i.item.path, i.item.line, t, p === 0 ? i.item.message : null];
        // A known hash agrees with an equal or unknown one; an unknown hash agrees with any.
        const ks =
          i.hash === null ? [key(...base, '*')] : [key(...base, '?'), key(...base, `#${i.hash}`)];
        for (const k of ks) {
          const run = runs.get(k);
          if (run) g.runs.push(run);
        }
      }
      if (g.runs.length > 0) reach.set(g, g.runs);
    }
    settle(new UnionFind(C + groups.length), reach);
  }

  // Passes 2 (same known hash, any distance) and 3 (same message, at most 20 lines apart).
  for (const p of [2, 3] as const) {
    pass = p;
    runOf = new Array<Run | undefined>(C);
    const maxDistance = p === 3 ? MESSAGE_PASS_MAX_LINES : Infinity;
    const buckets = new Map<string, LineBucket>();
    cands.forEach((c, ci) => {
      if (taken[ci] === 1 || c.line === null) return;
      const h = knownHash(c.sonarLineHash);
      if (p === 2 && h === null) return;
      const k = key(c.path, c.ruleKey, p === 2 ? h : c.message);
      let b = buckets.get(k);
      if (!b) {
        b = { lines: [], runs: [], right: new Int32Array(0), left: new Int32Array(0) };
        buckets.set(k, b);
      }
      // Candidates come by line, so each line's run is the bucket's last one or a new one.
      let run = b.lines.at(-1) === c.line ? b.runs.at(-1) : undefined;
      if (run === undefined) {
        const slot = { bucket: b, index: b.lines.length };
        run = { cands: [], free: 0, stamp: -1, slot, contested: false };
        b.lines.push(c.line);
        b.runs.push(run);
      }
      run.cands.push(ci);
      run.free++;
      runOf[ci] = run;
    });
    for (const b of buckets.values()) {
      b.right = Int32Array.from({ length: b.lines.length + 1 }, (_, i) => i);
      b.left = Int32Array.from({ length: b.lines.length + 1 }, (_, i) => i);
    }
    const groups = groupsOf((e) => {
      if (e.item.line === null) return null;
      if (p === 2) return e.hash === null ? null : key(e.item.path, e.item.line, e.hash);
      return e.item.message === null ? null : key(e.item.path, e.item.line, e.item.message);
    });
    const cursors = new Map<LineBucket, Cursor[]>();
    for (const g of groups) {
      const i = g.entries[0];
      if (i === undefined || i.item.line === null) continue;
      for (const t of i.targets) {
        const b = buckets.get(key(i.item.path, t, p === 2 ? i.hash : i.item.message));
        if (b === undefined) continue;
        const at = lowerBound(b.lines, i.item.line);
        const list = cursors.get(b) ?? [];
        list.push({ group: g, bucket: b, line: i.item.line, r: at, l: at - 1, d: 0 });
        cursors.set(b, list);
      }
    }

    // Contested candidates: items of different statuses reach them in this pass, at any
    // distance. They are never paired, make the component they fall in at any level ambiguous,
    // and are held back once the pass is over.
    for (const [b, list] of cursors) {
      if (p === 2) {
        if (new Set(list.map((c) => c.group.status)).size > 1)
          for (const run of b.runs) run.contested = true;
        continue;
      }
      // Pass 3: a sliding window of the cursors within 20 lines of each candidate line.
      const sorted = [...list].sort((x, y) => x.line - y.line);
      const count = new Map<StatusItemStatus, number>();
      const bump = (s: StatusItemStatus, by: number) => {
        const v = (count.get(s) ?? 0) + by;
        if (v === 0) count.delete(s);
        else count.set(s, v);
      };
      let lo = 0;
      let hi = 0;
      b.lines.forEach((line, index) => {
        for (let c = sorted[hi]; c !== undefined && c.line <= line + maxDistance; c = sorted[hi]) {
          bump(c.group.status, 1);
          hi++;
        }
        for (
          let c = sorted[lo];
          c !== undefined && lo < hi && c.line < line - maxDistance;
          c = sorted[lo]
        ) {
          bump(c.group.status, -1);
          lo++;
        }
        const run = b.runs[index];
        if (run && count.size > 1) run.contested = true;
      });
    }

    /** The distance of the cursor's nearest line with free candidates, or `Infinity`. */
    const nearest = (c: Cursor): number => {
      const b = c.bucket;
      const r = findRight(b, c.r);
      const l = c.l < 0 ? -1 : findLeft(b, c.l);
      c.r = r;
      c.l = l;
      const dr = r < b.lines.length ? (b.lines[r] ?? Infinity) - c.line : Infinity;
      const dl = l >= 0 ? c.line - (b.lines[l] ?? -Infinity) : Infinity;
      return Math.min(dr, dl);
    };
    const heap = new CursorHeap();
    const enqueue = (c: Cursor) => {
      if (openEntries(c.group).length === 0) return;
      c.d = nearest(c);
      if (Number.isFinite(c.d) && c.d <= maxDistance) heap.push(c);
    };
    for (const list of cursors.values()) for (const c of list) enqueue(c);

    const uf = new UnionFind(C + groups.length);
    while (heap.size > 0) {
      const d = heap.peek()?.d ?? Infinity;
      const reach = new Map<Group, Run[]>();
      const advanced: Cursor[] = [];
      while ((heap.peek()?.d ?? NaN) === d) {
        const c = heap.pop();
        if (c === undefined || openEntries(c.group).length === 0) continue;
        // Lines emptied since the cursor was queued are skipped: re-queue it farther.
        if (nearest(c) > d) {
          enqueue(c);
          continue;
        }
        const runs = reach.get(c.group) ?? [];
        const b = c.bucket;
        if (c.r < b.lines.length && (b.lines[c.r] ?? Infinity) - c.line === d) {
          const run = b.runs[c.r];
          if (run) runs.push(run);
          c.r++;
        }
        if (c.l >= 0 && c.line - (b.lines[c.l] ?? -Infinity) === d) {
          const run = b.runs[c.l];
          if (run) runs.push(run);
          c.l--;
        }
        reach.set(c.group, runs);
        advanced.push(c);
      }
      settle(uf, reach);
      for (const c of advanced) enqueue(c);
    }
    for (const b of buckets.values()) {
      for (const run of b.runs) if (run.contested) for (const ci of run.cands) take(ci);
    }
  }

  // Spec §10.5: a primary and its duplicate paired to items of different statuses. Mirroring
  // the primary's status onto the duplicate would give it a status its own counterpart does not
  // have; both items are ambiguous instead.
  const pairedTo = new Map<string, Entry>();
  for (const e of order) {
    const id = result.get(e.item.ref)?.candidateId;
    if (id !== null && id !== undefined) pairedTo.set(id, e);
  }
  for (const c of cands) {
    const primaryId = c.duplicateOf ?? null;
    if (primaryId === null) continue;
    const dup = pairedTo.get(c.id);
    const primary = pairedTo.get(primaryId);
    if (dup === undefined || primary === undefined) continue;
    if (dup.item.status === primary.item.status) continue;
    for (const e of [dup, primary]) {
      result.set(e.item.ref, { ref: e.item.ref, candidateId: null, pass: null, ambiguous: true });
    }
  }

  const unknown = unknownComponents(order, cands);
  holdMirroredDuplicates(order, cands, taken, result, unknown);
  return items.map((i) => ({
    ...(result.get(i.ref) ?? { ref: i.ref, candidateId: null, pass: null, ambiguous: false }),
    competitorsUnknown: unknown.has(i.ref),
  }));
}

/**
 * Spec §10.5 (final review I-1): a transition of a primary is mirrored onto its duplicates (ruling
 * I3), so a resolved item paired to a primary, or to a duplicate of a candidate, must not be
 * applied when the related candidate's own SonarQube counterpart is unsure: the candidate was held
 * back (an ambiguous group, or contested), or is paired to an `open` item or to one reported
 * `competitors_unknown`. Such a resolved item is made ambiguous, which holds its own candidate back
 * in turn, until nothing changes. A candidate no item reached is not unsure: its duplicate follows
 * its primary as usual. `result` is updated in place.
 */
function holdMirroredDuplicates(
  order: readonly Entry[],
  cands: readonly StatusCandidate[],
  taken: Uint8Array,
  result: Map<string, Omit<StatusMatch, 'competitorsUnknown'>>,
  unknown: ReadonlySet<string>,
): void {
  const index = new Map(cands.map((c, ci) => [c.id, ci]));
  /** Each candidate's related candidates: its primary and its duplicates. */
  const related = new Map<number, number[]>();
  const relate = (a: number, b: number) => related.set(a, [...(related.get(a) ?? []), b]);
  cands.forEach((c, ci) => {
    const primary = c.duplicateOf ?? null;
    const pi = primary === null ? undefined : index.get(primary);
    if (pi === undefined || pi === ci) return;
    relate(ci, pi);
    relate(pi, ci);
  });
  if (related.size === 0) return;
  /** Candidate → the item paired to it. */
  const holder = new Map<number, Entry>();
  for (const e of order) {
    const id = result.get(e.item.ref)?.candidateId ?? null;
    const ci = id === null ? undefined : index.get(id);
    if (ci !== undefined) holder.set(ci, e);
  }
  const unsure = new Uint8Array(cands.length);
  const queue: number[] = [];
  cands.forEach((_, ci) => {
    const h = holder.get(ci);
    const held = taken[ci] === 1 && h === undefined;
    if (held || (h !== undefined && (h.item.status === 'open' || unknown.has(h.item.ref)))) {
      unsure[ci] = 1;
      queue.push(ci);
    }
  });
  for (let ci = queue.pop(); ci !== undefined; ci = queue.pop()) {
    for (const r of related.get(ci) ?? []) {
      const h = holder.get(r);
      if (h === undefined || h.item.status === 'open' || unknown.has(h.item.ref)) continue;
      result.set(h.item.ref, { ref: h.item.ref, candidateId: null, pass: null, ambiguous: true });
      holder.delete(r);
      if (unsure[r] === 0) {
        unsure[r] = 1;
        queue.push(r);
      }
    }
  }
}

/**
 * Ruling S12: the refs of the items marked `competitorsUnknown` and of every item linked to one.
 * Items and candidates are linked when the candidate is on the item's path with a rule among its
 * targets (what every pass requires, whatever the rest of the evidence), candidates when one is
 * the other's duplicate.
 */
function unknownComponents(
  order: readonly Entry[],
  cands: readonly StatusCandidate[],
): Set<string> {
  const out = new Set<string>();
  if (!order.some((e) => e.item.competitorsUnknown === true)) return out;
  const C = cands.length;
  const uf = new UnionFind(C + order.length);
  const byPathRule = new Map<string, number>();
  const byId = new Map<string, number>();
  cands.forEach((c, ci) => {
    byId.set(c.id, ci);
    const k = key(c.path, c.ruleKey);
    const first = byPathRule.get(k);
    if (first === undefined) byPathRule.set(k, ci);
    else uf.union(first, ci);
  });
  cands.forEach((c, ci) => {
    const primary = c.duplicateOf ?? null;
    const p = primary === null ? undefined : byId.get(primary);
    if (p !== undefined) uf.union(p, ci);
  });
  order.forEach((e, n) => {
    for (const t of e.targets) {
      const ci = byPathRule.get(key(e.item.path, t));
      if (ci !== undefined) uf.union(C + n, ci);
    }
  });
  const roots = new Set<number>();
  order.forEach((e, n) => {
    if (e.item.competitorsUnknown === true) roots.add(uf.find(C + n));
  });
  order.forEach((e, n) => {
    if (roots.has(uf.find(C + n))) out.add(e.item.ref);
  });
  return out;
}
