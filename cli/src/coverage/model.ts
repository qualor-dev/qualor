import type { LineRange, ReportFile } from '@qualor/shared';

export type FileCoverage = NonNullable<ReportFile['coverage']>;

export interface BranchCounts {
  total: number;
  covered: number;
}

export const MAX_LINE = 10_000_000;
const validLine = (line: number) => Number.isInteger(line) && line >= 1 && line <= MAX_LINE;

/** One file's coverage as read from one report (ruling C12: maxima within a report). */
export class CoverageRecord {
  readonly lines = new Map<number, number>();
  readonly branches = new Map<number, BranchCounts>();

  hit(line: number, hits: number): void {
    if (!validLine(line) || !(hits >= 0)) return;
    this.lines.set(line, Math.max(this.lines.get(line) ?? 0, hits));
  }

  branch(line: number, total: number, covered: number): void {
    if (!validLine(line) || !(total > 0) || !Number.isFinite(total)) return;
    const hit = Math.min(Math.max(Number.isFinite(covered) ? covered : 0, 0), total);
    const prev = this.branches.get(line);
    this.branches.set(line, {
      total: Math.max(prev?.total ?? 0, total),
      covered: Math.max(prev?.covered ?? 0, hit),
    });
  }
}

export function recordFor(files: Map<string, CoverageRecord>, reportPath: string): CoverageRecord {
  let record = files.get(reportPath);
  if (record === undefined) {
    record = new CoverageRecord();
    files.set(reportPath, record);
  }
  return record;
}

export function toRanges(sortedLines: readonly number[]): LineRange[] {
  const out: LineRange[] = [];
  for (const line of sortedLines) {
    const last = out.at(-1);
    if (last !== undefined && line === last[1] + 1) last[1] = line;
    else out.push([line, line]);
  }
  return out;
}

/** Coverage of all reports per repo path (report-format §6: hits summed, branches maximum). */
export class CoverageAccumulator {
  private readonly files = new Map<string, CoverageRecord>();

  add(repoPath: string, record: CoverageRecord): void {
    const target = recordFor(this.files, repoPath);
    for (const [line, hits] of record.lines) target.lines.set(line, (target.lines.get(line) ?? 0) + hits);
    for (const [line, b] of record.branches) target.branch(line, b.total, b.covered);
  }

  paths(): string[] {
    return [...this.files.keys()].sort();
  }

  /** Lines past the end of the file (a stale report) are dropped and counted. */
  toFileCoverage(
    repoPath: string,
    lineCount: number,
  ): { coverage: FileCoverage; outOfRange: number } | undefined {
    const record = this.files.get(repoPath);
    if (record === undefined) return undefined;
    let outOfRange = 0;
    const covered: number[] = [];
    const uncovered: number[] = [];
    for (const [line, hits] of [...record.lines].sort((a, b) => a[0] - b[0])) {
      if (line > lineCount) outOfRange++;
      else if (hits > 0) covered.push(line);
      else uncovered.push(line);
    }
    const branches: [number, number, number][] = [];
    for (const [line, b] of [...record.branches].sort((a, c) => a[0] - c[0])) {
      if (line > lineCount) outOfRange++;
      else branches.push([line, b.total, b.covered]);
    }
    if (covered.length + uncovered.length + branches.length === 0) return undefined;
    return {
      coverage: { covered: toRanges(covered), uncovered: toRanges(uncovered), branches },
      outOfRange,
    };
  }
}
