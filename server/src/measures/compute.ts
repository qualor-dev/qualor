import {
  coverageMeasures,
  ratingFromSeverities,
  ratio,
  type CoverageCounts,
  type Quality,
  type Report,
  type ReportFile,
  type Severity,
} from '@qualor/shared';
import type { MeasureValues } from '../ingest/state';
import type { NewCodeClassifier } from '../newcode/lines';

/** report `files[].metrics` field → catalog key (gates.md §2). */
const SIZE_FIELDS = [
  ['ncloc', 'ncloc'],
  ['commentLines', 'comment_lines'],
  ['functions', 'functions'],
  ['classes', 'classes'],
  ['statements', 'statements'],
  ['complexity', 'complexity'],
  ['cognitiveComplexity', 'cognitive_complexity'],
] as const;

type LineRanges = readonly (readonly [number, number])[];

/**
 * A set of lines that counts by range arithmetic, never line by line: report line numbers are only
 * bounded by `Number.MAX_SAFE_INTEGER`, so a tiny report with `lines: 1e15` or a coverage range
 * `[1, 1e15]` must not turn into a loop (or a `Set`) of that size.
 */
export interface LineSet {
  /** How many lines of `[from, to]` (inclusive) are in the set. */
  count(from: number, to: number): number;
}

const ALL_LINES: LineSet = { count: (from, to) => Math.max(0, to - from + 1) };
const NO_LINES: LineSet = { count: () => 0 };

/** Sorted, disjoint, non-adjacent ranges covering the same lines as `ranges`. */
export function mergeRanges(ranges: LineRanges): [number, number][] {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [from, to] of sorted) {
    const last = merged.at(-1);
    if (last && from <= last[1] + 1) last[1] = Math.max(last[1], to);
    else merged.push([from, to]);
  }
  return merged;
}

/** `'all'`, ranges or nothing (report-format.md §6 `newLines`) as a {@link LineSet}. */
export function lineSet(ranges: LineRanges | 'all' | undefined): LineSet {
  if (ranges === 'all') return ALL_LINES;
  if (ranges === undefined || ranges.length === 0) return NO_LINES;
  const merged = mergeRanges(ranges);
  // before[i]: how many lines the ranges before merged[i] hold.
  const before: number[] = [];
  let total = 0;
  for (const [from, to] of merged) {
    before.push(total);
    total += to - from + 1;
  }
  /** Lines of the set that are ≤ `line`. */
  const upTo = (line: number): number => {
    let lo = 0;
    let hi = merged.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if ((merged[mid] as [number, number])[0] <= line) {
        found = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    if (found < 0) return 0;
    const [from, to] = merged[found] as [number, number];
    return (before[found] as number) + Math.min(line, to) - from + 1;
  };
  return { count: (from, to) => (to < from ? 0 : upTo(to) - upTo(from - 1)) };
}

/** `ranges` (merged) cut to the lines `1..lines` of a file. */
export function clampRanges(ranges: LineRanges, lines: number): [number, number][] {
  const out: [number, number][] = [];
  for (const [from, to] of ranges) {
    const a = Math.max(from, 1);
    const b = Math.min(to, lines);
    if (a <= b) out.push([a, b]);
  }
  return out;
}

/** The lines in both `a` and `b` (both merged: sorted and disjoint), merged. */
export function intersectRanges(a: LineRanges, b: LineRanges): [number, number][] {
  const out: [number, number][] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const [a0, a1] = a[i] as readonly [number, number];
    const [b0, b1] = b[j] as readonly [number, number];
    const from = Math.max(a0, b0);
    const to = Math.min(a1, b1);
    if (from <= to) out.push([from, to]);
    if (a1 < b1) i++;
    else j++;
  }
  return out;
}

/** The lines of `a` that are not in `b` (both merged), merged. */
export function subtractRanges(a: LineRanges, b: LineRanges): [number, number][] {
  const out: [number, number][] = [];
  let j = 0;
  for (const [a0, a1] of a) {
    let from = a0;
    while (j < b.length && (b[j] as readonly [number, number])[1] < from) j++;
    for (let k = j; from <= a1 && k < b.length; k++) {
      const [b0, b1] = b[k] as readonly [number, number];
      if (b0 > a1) break;
      if (b0 > from) out.push([from, b0 - 1]);
      from = Math.max(from, b1 + 1);
    }
    if (from <= a1) out.push([from, a1]);
  }
  return out;
}

/**
 * The new lines of one file for this analysis as merged ranges within `1..lines`: none when new
 * code is unavailable (baseline unavailable or first analysis), every line for `'all'`.
 */
export function newLineRanges(file: ReportFile, classifier: NewCodeClassifier): [number, number][] {
  if (!classifier.available || file.newLines === undefined) return [];
  if (file.newLines === 'all') return file.lines >= 1 ? [[1, file.lines]] : [];
  return clampRanges(mergeRanges(file.newLines), file.lines);
}

function rangeLength(ranges: LineRanges): number {
  return ranges.reduce((n, [from, to]) => n + (to - from + 1), 0);
}

/**
 * Per-file coverage counts (gates.md §2) over distinct lines within `1..lines`: overlapping or
 * repeated ranges count once, and a line listed both covered and uncovered counts as covered.
 * Conditions count once per line (the largest total and hit count reported for it). `only`
 * (merged ranges) restricts the counts to some lines (new code).
 */
export function fileCoverageCounts(
  coverage: NonNullable<ReportFile['coverage']>,
  lines: number,
  only?: LineRanges,
): CoverageCounts {
  let covered = clampRanges(mergeRanges(coverage.covered), lines);
  let uncovered = subtractRanges(clampRanges(mergeRanges(coverage.uncovered), lines), covered);
  if (only) {
    covered = intersectRanges(covered, only);
    uncovered = intersectRanges(uncovered, only);
  }
  const keep = only ? lineSet(only) : ALL_LINES;
  const byLine = new Map<number, [number, number]>();
  for (const [line, total, hit] of coverage.branches) {
    if (line > lines || keep.count(line, line) === 0) continue;
    const seen = byLine.get(line);
    if (seen) {
      seen[0] = Math.max(seen[0], total);
      seen[1] = Math.max(seen[1], hit);
    } else byLine.set(line, [total, hit]);
  }
  let conditions = 0;
  let coveredConditions = 0;
  for (const [total, hit] of byLine.values()) {
    conditions += total;
    coveredConditions += hit;
  }
  const coveredLines = rangeLength(covered);
  const uncoveredLines = rangeLength(uncovered);
  return {
    linesToCover: coveredLines + uncoveredLines,
    uncoveredLines,
    conditionsToCover: conditions,
    uncoveredConditions: conditions - coveredConditions,
  };
}

function addCounts(a: CoverageCounts, b: CoverageCounts): CoverageCounts {
  return {
    linesToCover: a.linesToCover + b.linesToCover,
    uncoveredLines: a.uncoveredLines + b.uncoveredLines,
    conditionsToCover: a.conditionsToCover + b.conditionsToCover,
    uncoveredConditions: a.uncoveredConditions + b.uncoveredConditions,
  };
}

const ZERO: CoverageCounts = {
  linesToCover: 0,
  uncoveredLines: 0,
  conditionsToCover: 0,
  uncoveredConditions: 0,
};

/** Duplication of one main file: its blocks, and the distinct lines they cover. */
export interface FileDuplicationCounts {
  /** Merged ranges of the duplicated lines, within `1..lines` of the file. */
  ranges: [number, number][];
  /** Distinct duplicated lines. */
  lines: number;
  /** The file's blocks as `[startLine, endLine]` (one small tuple per reported block). */
  blocks: [number, number][];
}

/** Duplicated lines and blocks per main file (report-format.md §8; test files are ignored). */
export function duplicationByFile(report: Report): Map<string, FileDuplicationCounts> {
  const lengths = new Map(
    report.files.filter((f) => f.kind === 'main').map((f) => [f.path, f.lines]),
  );
  const blocksByFile = new Map<string, [number, number][]>();
  for (const group of report.duplications) {
    for (const block of group.blocks) {
      if (!lengths.has(block.path)) continue;
      let list = blocksByFile.get(block.path);
      if (!list) blocksByFile.set(block.path, (list = []));
      list.push([block.startLine, block.endLine]);
    }
  }
  const byFile = new Map<string, FileDuplicationCounts>();
  for (const [path, blocks] of blocksByFile) {
    const ranges = clampRanges(mergeRanges(blocks), lengths.get(path) ?? 0);
    byFile.set(path, { ranges, lines: rangeLength(ranges), blocks });
  }
  return byFile;
}

/**
 * gates.md §2–§3 measures that come from the report alone: size and complexity (overall), and
 * coverage, duplication and `lines` (overall and new). Only `kind: main` files count (ruling M1).
 * `new_*` values are null when the baseline is unavailable; on a first analysis there is no new
 * code, so counts are 0 and ratios null.
 */
export function reportMeasures(report: Report, classifier: NewCodeClassifier): MeasureValues {
  const baseline = report.scm.baseline.status;
  const mainFiles = report.files.filter((f) => f.kind === 'main');
  const values: MeasureValues = {};

  const lines = mainFiles.reduce((n, f) => n + f.lines, 0);
  values.files = mainFiles.length;
  values.lines = lines;
  for (const [field, key] of SIZE_FIELDS) {
    values[key] = mainFiles.reduce((n, f) => n + (f.metrics?.[field] ?? 0), 0);
  }

  const newRanges = new Map(mainFiles.map((f) => [f.path, newLineRanges(f, classifier)]));
  const isNew = (path: string): [number, number][] => newRanges.get(path) ?? [];
  let newLines = 0;
  for (const ranges of newRanges.values()) newLines += rangeLength(ranges);

  const covered = mainFiles.filter((f) => f.coverage !== undefined);
  let overall = ZERO;
  let fresh = ZERO;
  for (const f of covered) {
    if (!f.coverage) continue;
    overall = addCounts(overall, fileCoverageCounts(f.coverage, f.lines));
    fresh = addCounts(fresh, fileCoverageCounts(f.coverage, f.lines, isNew(f.path)));
  }
  const overallCoverage = coverageMeasures(covered.length === 0 ? null : overall);
  const newCoverage = coverageMeasures(covered.length === 0 ? null : fresh);

  let duplicatedLines = 0;
  let duplicatedBlocks = 0;
  let newDuplicatedLines = 0;
  let newDuplicatedBlocks = 0;
  for (const [path, entry] of duplicationByFile(report)) {
    const fresh = isNew(path);
    const test = lineSet(fresh);
    duplicatedLines += entry.lines;
    duplicatedBlocks += entry.blocks.length;
    newDuplicatedLines += rangeLength(intersectRanges(entry.ranges, fresh));
    for (const [from, to] of entry.blocks) if (test.count(from, to) > 0) newDuplicatedBlocks++;
  }

  for (const [key, value] of Object.entries(overallCoverage)) values[key] = value;
  values.duplicated_lines = duplicatedLines;
  values.duplicated_blocks = duplicatedBlocks;
  values.duplicated_lines_density = ratio(duplicatedLines, lines);

  const unavailable = baseline === 'unavailable';
  const newValue = (v: number | null) => (unavailable ? null : v);
  values.new_lines = newValue(newLines);
  for (const [key, value] of Object.entries(newCoverage)) values[`new_${key}`] = newValue(value);
  values.new_duplicated_lines = newValue(newDuplicatedLines);
  values.new_duplicated_blocks = newValue(newDuplicatedBlocks);
  values.new_duplicated_lines_density = newValue(ratio(newDuplicatedLines, newLines));
  return values;
}

/** One visible-issue count group, as the aggregation query returns it. */
export interface IssueCountRow {
  severity: Severity;
  quality: Quality;
  inNewCode: boolean;
  count: number;
}

const SEVERITY_KEYS: readonly Severity[] = ['blocker', 'high', 'medium', 'low', 'info'];
const QUALITY_KEYS: readonly Quality[] = ['security', 'reliability', 'maintainability'];

/**
 * gates.md §2 issue counts and ratings. `rows` are visible issues only (open, not a duplicate,
 * kind issue); `accepted` and `falsePositives` count wont_fix and false_positive issues.
 */
export function issueMeasures(
  rows: readonly IssueCountRow[],
  accepted: number,
  falsePositives: number,
  baselineUnavailable: boolean,
): MeasureValues {
  const values: MeasureValues = {};
  for (const scope of ['overall', 'new'] as const) {
    const inScope = rows.filter((r) => scope === 'overall' || r.inNewCode);
    const prefix = scope === 'new' ? 'new_' : '';
    const sum = (keep: (r: IssueCountRow) => boolean) =>
      inScope.filter(keep).reduce((n, r) => n + r.count, 0);
    const set = (key: string, value: number) => {
      values[`${prefix}${key}`] = scope === 'new' && baselineUnavailable ? null : value;
    };
    set(
      'issues',
      sum(() => true),
    );
    for (const s of SEVERITY_KEYS)
      set(
        `${s}_issues`,
        sum((r) => r.severity === s),
      );
    for (const q of QUALITY_KEYS)
      set(
        `${q}_issues`,
        sum((r) => r.quality === q),
      );
    for (const q of ['security', 'reliability'] as const) {
      const severities = inScope
        .filter((r) => r.quality === q && r.count > 0)
        .map((r) => r.severity);
      set(`${q}_rating`, ratingFromSeverities(severities));
    }
  }
  values.accepted_issues = accepted;
  values.false_positive_issues = falsePositives;
  return values;
}
