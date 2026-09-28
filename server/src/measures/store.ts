import { allMetricKeys, type Quality, type Report, type Severity } from '@qualor/shared';
import { and, eq, inArray, isNull, sql } from 'drizzle-orm';
import { jsonChunks } from '../db/bulk';
import type { Executor } from '../db/client';
import { branchFiles, issues } from '../db/schema';
import type { MeasureValues } from '../ingest/state';
import type { NewCodeClassifier } from '../newcode/lines';
import {
  duplicationByFile,
  fileCoverageCounts,
  newLineRanges,
  type IssueCountRow,
} from './compute';

/** gates.md §2: visible issues are open, not a duplicate, and of kind `issue`. */
export async function visibleIssueCounts(tx: Executor, branchId: string): Promise<IssueCountRow[]> {
  const rows = await tx
    .select({
      severity: issues.severity,
      quality: issues.quality,
      inNewCode: issues.inNewCode,
      count: sql<number>`count(*)::int`,
    })
    .from(issues)
    .where(
      and(
        eq(issues.branchId, branchId),
        eq(issues.status, 'open'),
        isNull(issues.duplicateOfIssueId),
        eq(issues.kind, 'issue'),
      ),
    )
    .groupBy(issues.severity, issues.quality, issues.inNewCode);
  return rows.map((r) => ({
    severity: r.severity as Severity,
    quality: r.quality as Quality,
    inNewCode: r.inNewCode,
    count: r.count,
  }));
}

/** `accepted_issues` (wont_fix) and `false_positive_issues`: kind `issue`, duplicates excluded (ruling M1). */
export async function resolvedIssueCounts(
  tx: Executor,
  branchId: string,
): Promise<{ accepted: number; falsePositives: number }> {
  const rows = await tx
    .select({ status: issues.status, count: sql<number>`count(*)::int` })
    .from(issues)
    .where(
      and(
        eq(issues.branchId, branchId),
        inArray(issues.status, ['wont_fix', 'false_positive']),
        isNull(issues.duplicateOfIssueId),
        eq(issues.kind, 'issue'),
      ),
    )
    .groupBy(issues.status);
  const count = (status: string) => rows.find((r) => r.status === status)?.count ?? 0;
  return { accepted: count('wont_fix'), falsePositives: count('false_positive') };
}

/**
 * One `measures` row per catalog metric and scope (data-model.md §4.3): `metric_key` is the base
 * key and `scope` says overall or new, so `new_coverage` is stored as (`coverage`, `new`).
 */
export async function writeMeasures(
  tx: Executor,
  analysisId: string,
  values: MeasureValues,
): Promise<void> {
  const rows = allMetricKeys().map((key) => {
    const isNew = key.startsWith('new_');
    return {
      metric_key: isNew ? key.slice(4) : key,
      scope: isNew ? 'new' : 'overall',
      value: values[key] ?? null,
    };
  });
  for (const chunk of jsonChunks(rows)) {
    await tx.execute(sql`
      INSERT INTO measures (analysis_id, metric_key, scope, value)
      SELECT ${analysisId}, r.metric_key, r.scope, r.value
      FROM jsonb_to_recordset(${chunk}::jsonb)
        AS r(metric_key text, scope text, value double precision)`);
  }
}

/** A branch_files.duplications entry: one block of this file and (some of) the blocks it duplicates. */
export interface FileDuplication {
  startLine: number;
  endLine: number;
  /** At most {@link MAX_DUPLICATION_OTHERS} of the other blocks of its group. */
  others: { path: string; startLine: number; endLine: number }[];
  /** How many other blocks the group has (`others.length` when none were cut). */
  othersTotal: number;
}

/**
 * Bounds on the stored duplication detail (`branch_files.duplications`). A report may hold 100 000
 * groups of up to 1 000 blocks (report-format.md §8), so listing every partner of every block is
 * quadratic, and even a per-block cap multiplies the input: a few MB of report became a 400 MB
 * jsonb. Line and block counts (`metrics`, `measures`) always use every block; only the listed
 * detail is cut, and the cut is recorded (`othersTotal`, `metrics.duplicationEntries`).
 */
export const MAX_DUPLICATION_OTHERS = 10;
/** Entries stored per file, and a byte budget per file row. */
export const MAX_FILE_DUPLICATIONS = 1_000;
export const MAX_FILE_DUPLICATION_BYTES = 1024 * 1024;
/** Entries and bytes stored per analysis, over all files. */
export const MAX_ANALYSIS_DUPLICATIONS = 50_000;
export const MAX_ANALYSIS_DUPLICATION_BYTES = 32 * 1024 * 1024;

/** Rough JSON size of an entry: fixed keys and numbers, plus each listed partner's encoded path. */
const ENTRY_BYTES = 64;
const PARTNER_BYTES = 48;

interface DuplicationIndex {
  /** Per file: `[group, block]` index pairs (flattened) of the entries that will be stored. */
  kept: Map<string, number[]>;
  /** Per file: every block of the report on that file (stored or not). */
  totals: Map<string, number>;
}

/**
 * Picks which duplication entries are stored, within the bounds above, keeping only index pairs
 * (never copies of blocks): memory stays proportional to what is stored, not to the report.
 */
function indexDuplications(report: Report): DuplicationIndex {
  const files = new Set(report.files.map((f) => f.path));
  const kept = new Map<string, number[]>();
  const totals = new Map<string, number>();
  const fileBytes = new Map<string, number>();
  // A path's size as written: JSON-escaped (a control character becomes six bytes) and UTF-8
  // encoded (up to four bytes per character), not its UTF-16 length. Paths repeat across
  // blocks, so each is measured once.
  const pathSizes = new Map<string, number>();
  const pathBytes = (path: string): number => {
    let size = pathSizes.get(path);
    if (size === undefined) {
      size = Buffer.byteLength(JSON.stringify(path), 'utf8');
      pathSizes.set(path, size);
    }
    return size;
  };
  let entries = 0;
  let bytes = 0;
  report.duplications.forEach((group, g) => {
    group.blocks.forEach((block, b) => {
      if (!files.has(block.path)) return;
      totals.set(block.path, (totals.get(block.path) ?? 0) + 1);
      if (entries >= MAX_ANALYSIS_DUPLICATIONS) return;
      const list = kept.get(block.path) ?? [];
      if (list.length / 2 >= MAX_FILE_DUPLICATIONS) return;
      let cost = ENTRY_BYTES;
      for (let i = 0, n = 0; i < group.blocks.length && n < MAX_DUPLICATION_OTHERS; i++) {
        const other = group.blocks[i];
        if (i === b || !other) continue;
        cost += PARTNER_BYTES + pathBytes(other.path);
        n++;
      }
      const used = fileBytes.get(block.path) ?? 0;
      if (used + cost > MAX_FILE_DUPLICATION_BYTES || bytes + cost > MAX_ANALYSIS_DUPLICATION_BYTES)
        return;
      list.push(g, b);
      kept.set(block.path, list);
      fileBytes.set(block.path, used + cost);
      entries++;
      bytes += cost;
    });
  });
  return { kept, totals };
}

function fileDuplications(report: Report, pairs: readonly number[]): FileDuplication[] {
  const out: FileDuplication[] = [];
  for (let p = 0; p + 1 < pairs.length; p += 2) {
    const g = pairs[p] as number;
    const b = pairs[p + 1] as number;
    const blocks = report.duplications[g]?.blocks ?? [];
    const block = blocks[b];
    if (!block) continue;
    const others: FileDuplication['others'] = [];
    for (let i = 0; i < blocks.length && others.length < MAX_DUPLICATION_OTHERS; i++) {
      const other = blocks[i];
      if (i !== b && other) {
        others.push({ path: other.path, startLine: other.startLine, endLine: other.endLine });
      }
    }
    out.push({
      startLine: block.startLine,
      endLine: block.endLine,
      others,
      othersTotal: blocks.length - 1,
    });
  }
  return out;
}

/**
 * data-model.md §4.3: `branch_files` is a snapshot of the latest analysis only, replaced in the
 * ingestion transaction. `metrics` holds the report's per-file metrics plus the counts the file
 * tree aggregates in SQL: `lines`, `newLines` (only when new code is available), coverage counts
 * (only when the file was covered), `duplicatedLines`/`duplicatedBlocks`, and
 * `duplicationEntries` (every block on the file, of which `duplications` lists a bounded part).
 * Rows are built lazily, one chunk at a time.
 */
export async function replaceBranchFiles(
  tx: Executor,
  branchId: string,
  analysisId: string,
  report: Report,
  classifier: NewCodeClassifier,
): Promise<void> {
  await tx.delete(branchFiles).where(eq(branchFiles.branchId, branchId));
  const duplicated = duplicationByFile(report);
  const { kept, totals } = indexDuplications(report);
  function* rows() {
    for (const f of report.files) {
      const metrics: Record<string, number> = { lines: f.lines, ...(f.metrics ?? {}) };
      if (classifier.available) {
        metrics.newLines = newLineRanges(f, classifier).reduce((n, [a, b]) => n + b - a + 1, 0);
      }
      if (f.coverage) {
        const c = fileCoverageCounts(f.coverage, f.lines);
        metrics.linesToCover = c.linesToCover;
        metrics.uncoveredLines = c.uncoveredLines;
        metrics.conditionsToCover = c.conditionsToCover;
        metrics.uncoveredConditions = c.uncoveredConditions;
      }
      const dup = duplicated.get(f.path);
      metrics.duplicatedLines = dup?.lines ?? 0;
      metrics.duplicatedBlocks = dup?.blocks.length ?? 0;
      metrics.duplicationEntries = totals.get(f.path) ?? 0;
      yield {
        path: f.path,
        language: f.language,
        kind: f.kind,
        sha256: f.sha256,
        metrics,
        coverage: f.coverage ?? null,
        new_lines: classifier.available ? (f.newLines ?? null) : null,
        duplications: fileDuplications(report, kept.get(f.path) ?? []),
      };
    }
  }
  for (const chunk of jsonChunks(rows())) {
    await tx.execute(sql`
      INSERT INTO branch_files (branch_id, path, language, kind, sha256, metrics, coverage,
        new_lines, duplications, analysis_id)
      SELECT ${branchId}, r.path, r.language, r.kind, r.sha256, r.metrics, r.coverage,
        r.new_lines, r.duplications, ${analysisId}
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(path text, language text, kind text,
        sha256 text, metrics jsonb, coverage jsonb, new_lines jsonb, duplications jsonb)`);
  }
}
