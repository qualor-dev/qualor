import type { Report, ReportFile } from '@qualor/shared';

/** `files[].newLines` of report-format.md §6. */
export type NewLines = ReportFile['newLines'];

/**
 * A membership test for a file's new lines: `'all'` (an added file) contains every line, a
 * missing `newLines` contains none, and ranges (1-based, inclusive, possibly unsorted or
 * overlapping) are merged once and then binary-searched.
 */
export function newLineTest(newLines: NewLines): (line: number) => boolean {
  if (newLines === 'all') return () => true;
  if (newLines === undefined || newLines.length === 0) return () => false;
  const sorted = [...newLines].sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [from, to] of sorted) {
    const last = merged.at(-1);
    if (last && from <= last[1] + 1) last[1] = Math.max(last[1], to);
    else merged.push([from, to]);
  }
  return (line) => {
    let lo = 0;
    let hi = merged.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const [from, to] = merged[mid] as [number, number];
      if (line < from) hi = mid - 1;
      else if (line > to) lo = mid + 1;
      else return true;
    }
    return false;
  };
}

/** Classifies issues as new code for one analysis (gates.md §5, "Issue classification"). */
export interface NewCodeClassifier {
  /** Whether new code exists at all: false when the baseline is unavailable or this is a first
   *  analysis — then no issue is in new code (and new_* measures are null or 0, gates.md §3). */
  readonly available: boolean;
  isNewLine(path: string, line: number): boolean;
  /**
   * `in_new_code` of an issue: its primary `start_line` lies in its file's new lines. A file-less
   * issue is new iff it was first seen in this analysis (`firstSeenNow`: created by this analysis
   * and not inherited from the reference branch).
   */
  inNewCode(path: string | null, line: number | null, firstSeenNow: boolean): boolean;
}

export function newCodeClassifier(report: Report): NewCodeClassifier {
  const available = report.scm.baseline.status === 'ok';
  const tests = new Map<string, (line: number) => boolean>();
  const byPath = new Map(report.files.map((f) => [f.path, f]));
  const isNewLine = (path: string, line: number): boolean => {
    if (!available) return false;
    let test = tests.get(path);
    if (!test) {
      test = newLineTest(byPath.get(path)?.newLines);
      tests.set(path, test);
    }
    return test(line);
  };
  return {
    available,
    isNewLine,
    inNewCode: (path, line, firstSeenNow) => {
      if (!available) return false;
      if (path === null) return firstSeenNow;
      return line !== null && isNewLine(path, line);
    },
  };
}
