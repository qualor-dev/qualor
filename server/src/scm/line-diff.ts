/**
 * Lines a file version added relative to another (Azure DevOps has no line-level diff API, so
 * the pull request's added lines are computed from the file at the base and head commits).
 */

export interface LineDiffOptions {
  /** Either side longer than this gives up (default 20 000 lines). */
  maxLines?: number;
  /** An edit distance (insertions + deletions) above this gives up (default 2 000). */
  maxEdits?: number;
}

/**
 * More than 2 000 line edits after trimming is a rewrite, not a change: its findings count as
 * unplaced. The cap also bounds the O(D^2) trace (about 8 MB) and the search (about 80M steps).
 */
const DEFAULT_MAX_LINES = 20_000;
const DEFAULT_MAX_EDITS = 2_000;

/** Split on `\n`, drop one trailing `\r` per line and the empty piece after a final newline. */
function splitLines(text: string): string[] {
  if (text === '') return [];
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines.map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
}

/**
 * 1-based line numbers of `head` that are added relative to `base` (every line when `base` is
 * null), with their text. Null when either side exceeds `maxLines` or the shortest edit script
 * is longer than `maxEdits`.
 */
export function addedLines(
  base: string | null,
  head: string,
  options: LineDiffOptions = {},
): Map<number, string> | null {
  const maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
  const maxEdits = options.maxEdits ?? DEFAULT_MAX_EDITS;
  const b = base === null ? [] : splitLines(base);
  const h = splitLines(head);
  if (b.length > maxLines || h.length > maxLines) return null;

  const added = new Map<number, string>();
  if (base === null) {
    h.forEach((text, i) => added.set(i + 1, text));
    return added;
  }

  let start = 0;
  while (start < b.length && start < h.length && b[start] === h[start]) start++;
  let bEnd = b.length;
  let hEnd = h.length;
  while (bEnd > start && hEnd > start && b[bEnd - 1] === h[hEnd - 1]) {
    bEnd--;
    hEnd--;
  }
  const inserted = shortestScript(b.slice(start, bEnd), h.slice(start, hEnd), maxEdits);
  if (inserted === null) return null;
  for (const i of inserted) added.set(start + i + 1, h[start + i] ?? '');
  return added;
}

/**
 * Myers' O((N+M)·D) shortest edit script; returns the 0-based indices of `h` that are
 * insertions, or null once D passes `maxEdits`. On ties a deletion is preferred to an
 * insertion (git's choice). `trace[d]` holds the furthest x of every diagonal after round d,
 * the diagonal k at index (k + d) / 2.
 */
function shortestScript(b: string[], h: string[], maxEdits: number): number[] | null {
  const n = b.length;
  const m = h.length;
  if (n + m === 0) return [];
  const limit = Math.min(maxEdits, n + m);
  const trace: Int32Array[] = [];
  for (let d = 0; d <= limit; d++) {
    const cur = new Int32Array(d + 1);
    const prev = d > 0 ? (trace[d - 1] ?? null) : null;
    for (let k = -d; k <= d; k += 2) {
      let x: number;
      if (prev === null) {
        x = 0;
      } else if (
        k === -d ||
        (k !== d && furthest(prev, k - 1, d - 1) < furthest(prev, k + 1, d - 1))
      ) {
        x = furthest(prev, k + 1, d - 1);
      } else {
        x = furthest(prev, k - 1, d - 1) + 1;
      }
      let y = x - k;
      while (x < n && y < m && b[x] === h[y]) {
        x++;
        y++;
      }
      cur[(k + d) >> 1] = x;
      if (x >= n && y >= m) {
        trace.push(cur);
        return backtrack(trace, d, n, m);
      }
    }
    trace.push(cur);
  }
  return null;
}

/** Furthest x on diagonal k after round r. */
function furthest(round: Int32Array, k: number, r: number): number {
  return round[(k + r) >> 1] ?? 0;
}

function backtrack(trace: Int32Array[], dEnd: number, n: number, m: number): number[] {
  const inserted: number[] = [];
  let x = n;
  let y = m;
  for (let d = dEnd; d > 0; d--) {
    const prev = trace[d - 1] ?? new Int32Array(0);
    const k = x - y;
    const down =
      k === -d || (k !== d && furthest(prev, k - 1, d - 1) < furthest(prev, k + 1, d - 1));
    const prevK = down ? k + 1 : k - 1;
    const prevX = furthest(prev, prevK, d - 1);
    const prevY = prevX - prevK;
    if (down) inserted.push(prevY);
    x = prevX;
    y = prevY;
  }
  return inserted.reverse();
}
