import type { ResponseBody } from '../../api/types';

/** `GET /branches/{id}/file` (spec §4.3): one file's measures, line lists and issues. */
export type FileDetail = ResponseBody<'/api/v0/branches/{id}/file', 'get'>;

export type CoverageState = 'covered' | 'uncovered' | 'partial' | 'none';
/** Lines `from` to `to`, both included, 1-based. */
export interface Run {
  from: number;
  to: number;
}
export interface Lane<T> {
  runs: (Run & { value: T })[];
}
/**
 * A file as the line map draws it: every lane is a list of runs of lines, never one entry per
 * line, so a 50 000-line file costs as much as its number of changes of state.
 */
export interface LineMap {
  lines: number;
  coverage: Lane<CoverageState>;
  newCode: Run[];
  duplication: Run[];
  issues: { line: number; severity: string; id: string }[];
}

/** The range inside `1..lines`, or null when nothing of it is. */
function clip(from: number, to: number, lines: number): Run | null {
  const a = Math.max(1, Math.floor(from));
  const b = Math.min(lines, Math.floor(to));
  return Number.isFinite(a) && Number.isFinite(b) && a <= b ? { from: a, to: b } : null;
}

/** Clipped, sorted, and with overlapping or adjacent ranges joined. */
function mergeRanges(ranges: readonly (readonly [number, number])[], lines: number): Run[] {
  const runs = ranges
    .map(([from, to]) => clip(from, to, lines))
    .filter((r): r is Run => r !== null)
    .sort((x, y) => x.from - y.from);
  const out: Run[] = [];
  for (const r of runs) {
    const last = out.at(-1);
    if (last && r.from <= last.to + 1) last.to = Math.max(last.to, r.to);
    else out.push({ ...r });
  }
  return out;
}

/**
 * Coverage as runs of equal state. A line with conditions of which not all were taken is partly
 * covered: it overrides covered (and a line in neither list), never uncovered.
 */
function coverageRuns(coverage: FileDetail['coverage'], lines: number): Lane<CoverageState> {
  if (!coverage) return { runs: [] };
  const uncovered = mergeRanges(coverage.uncovered, lines);
  const covered = mergeRanges(coverage.covered, lines);
  const inUncovered = (line: number) => find(uncovered, line) !== null;
  const partial = [
    ...new Set(
      coverage.branches
        .filter(([line, total, taken]) => taken < total && line >= 1 && line <= lines)
        .map(([line]) => Math.floor(line))
        .filter((line) => !inUncovered(line)),
    ),
  ].sort((a, b) => a - b);

  const pieces: (Run & { value: CoverageState })[] = [];
  for (const r of uncovered) pieces.push({ ...r, value: 'uncovered' });
  const point = (line: number) => ({ from: line, to: line, value: 'partial' as const });
  let p = 0;
  for (const r of covered) {
    let from = r.from;
    for (let line = partial[p]; line !== undefined && line <= r.to; line = partial[++p]) {
      // A partly covered line before this run is in no list of lines.
      if (line >= from) {
        if (line > from) pieces.push({ from, to: line - 1, value: 'covered' });
        from = line + 1;
      }
      pieces.push(point(line));
    }
    if (from <= r.to) pieces.push({ from, to: r.to, value: 'covered' });
  }
  for (const line of partial.slice(p)) pieces.push(point(line));

  // A line the server listed as both covered and uncovered is shown uncovered (its first run).
  pieces.sort((x, y) => x.from - y.from || (x.value === 'uncovered' ? -1 : 1));
  const runs: (Run & { value: CoverageState })[] = [];
  for (const piece of pieces) {
    const last = runs.at(-1);
    const from = last ? Math.max(piece.from, last.to + 1) : piece.from;
    if (from > piece.to) continue;
    if (last && last.value === piece.value && from === last.to + 1) last.to = piece.to;
    else runs.push({ from, to: piece.to, value: piece.value });
  }
  return { runs };
}

export function buildLineMap(detail: FileDetail): LineMap {
  const raw = detail.measures['lines'];
  const lines = typeof raw === 'number' && Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 0;
  const newLines = detail.newLines;
  return {
    lines,
    coverage: coverageRuns(detail.coverage, lines),
    newCode:
      newLines === 'all'
        ? lines > 0
          ? [{ from: 1, to: lines }]
          : []
        : mergeRanges(newLines ?? [], lines),
    duplication: mergeRanges(
      detail.duplications.map((d) => [d.startLine, d.endLine] as const),
      lines,
    ),
    issues: detail.issues
      .filter(
        (i): i is typeof i & { startLine: number } =>
          i.startLine !== null && i.startLine >= 1 && i.startLine <= lines,
      )
      .map((i) => ({ line: i.startLine, severity: i.severity, id: i.id }))
      .sort((a, b) => a.line - b.line),
  };
}

/** The run holding the line (binary search over sorted, disjoint runs). */
function find<R extends Run>(runs: readonly R[], line: number): R | null {
  let lo = 0;
  let hi = runs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = runs[mid];
    if (!r) return null;
    if (line < r.from) hi = mid - 1;
    else if (line > r.to) lo = mid + 1;
    else return r;
  }
  return null;
}

/** What is on one line, in every lane. */
export function lineInfo(
  map: LineMap,
  line: number,
): { coverage: CoverageState; newCode: boolean; duplicated: boolean; issues: number } {
  return {
    coverage: find(map.coverage.runs, line)?.value ?? 'none',
    newCode: find(map.newCode, line) !== null,
    duplicated: find(map.duplication, line) !== null,
    issues: map.issues.filter((i) => i.line === line).length,
  };
}

/** Lines per coverage state and of new code, and the issue markers: the map's text summary. */
export function lineCounts(map: LineMap): {
  covered: number;
  uncovered: number;
  partial: number;
  newCode: number;
  issues: number;
} {
  const size = (r: Run) => r.to - r.from + 1;
  const of = (state: CoverageState) =>
    map.coverage.runs.filter((r) => r.value === state).reduce((n, r) => n + size(r), 0);
  return {
    covered: of('covered'),
    uncovered: of('uncovered'),
    partial: of('partial'),
    newCode: map.newCode.reduce((n, r) => n + size(r), 0),
    issues: map.issues.length,
  };
}
