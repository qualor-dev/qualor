import { createReadStream, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import type { ParsedCoverage } from './lcov';
import { MAX_LINE, recordFor, type CoverageRecord } from './model';

/** `go test -coverprofile`'s first line (repeated when profiles are concatenated). */
export const GO_COVER_MODE = /^mode: (set|count|atomic)$/;
/** `<import path>/<file>.go:<line>.<col>,<line>.<col> <statements> <count>`. */
const BLOCK = /^(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$/;

/** The profile comes from the CI and is not trusted: a file this large is refused unread. */
export const MAX_GO_COVER_BYTES = 128 * 1024 * 1024;
/** A block this long (or one starting past the line limit) is not Go source; it is skipped. */
const MAX_BLOCK_LINES = 100_000;
/** Distinct lines kept over all files (growth of the line maps); more are not added (memory). */
const MAX_DISTINCT_LINES = 20_000_000;
/** Line visits over all blocks, repeats included; bounds the time a small file can cost. */
const MAX_LINE_VISITS = 400_000_000;

/** A path that climbs out of the repository with `..` is never mapped onto a file. */
const climbs = (file: string) => file.replaceAll('\\', '/').split('/').includes('..');

/**
 * A Go coverage profile (config.md §6, plan 9C). A block with at least one statement makes its
 * lines executable; its last line only when the block ends past column 1 (the `}` of a function
 * body is not a statement). A line's hits are the maximum over its blocks (CoverageRecord.hit).
 * Paths are import paths, resolved to repository files by suffix (PathResolver, which only ever
 * returns analysed repository files); `_/abs/path` is what go writes outside a module. Entries
 * with `..` segments are dropped.
 */
export async function parseGoCover(
  absPath: string,
  limits: { distinctLines: number; lineVisits: number } = {
    distinctLines: MAX_DISTINCT_LINES,
    lineVisits: MAX_LINE_VISITS,
  },
): Promise<ParsedCoverage> {
  let size: number;
  try {
    size = statSync(absPath).size;
  } catch {
    throw new Error('cannot read the Go coverage profile');
  }
  if (size > MAX_GO_COVER_BYTES) {
    throw new Error(`Go coverage profile too large (over ${MAX_GO_COVER_BYTES} bytes)`);
  }
  const files = new Map<string, CoverageRecord>();
  let sawMode = false;
  let distinct = 0;
  let visits = 0;
  let truncated = false;
  const lines = createInterface({
    input: createReadStream(absPath, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  for await (const raw of lines) {
    const line = raw.replace(/^\uFEFF/, '').trim();
    if (line === '') continue;
    if (GO_COVER_MODE.test(line)) {
      sawMode = true;
      continue;
    }
    if (!sawMode) throw new Error('not a Go coverage profile (no mode line)');
    const m = BLOCK.exec(line);
    if (m === null) throw new Error(`unexpected line in a Go coverage profile: ${line.slice(0, 80)}`);
    const [, file = '', l1, , l2, c2, statements, count] = m;
    if (Number(statements) === 0 || climbs(file)) continue;
    const start = Number(l1);
    const end = Number(c2) <= 1 && Number(l2) > start ? Number(l2) - 1 : Number(l2);
    if (start < 1 || start > MAX_LINE || end < start || end - start >= MAX_BLOCK_LINES) continue;
    if (truncated) continue; // keep reading to validate the rest, add nothing
    visits += end - start + 1;
    if (visits > limits.lineVisits) {
      truncated = true;
      continue;
    }
    const record = recordFor(files, file.startsWith('_/') ? file.slice(1) : file);
    const before = record.lines.size;
    for (let l = start; l <= end; l++) record.hit(l, Number(count));
    distinct += record.lines.size - before;
    if (distinct > limits.distinctLines) truncated = true;
  }
  if (!sawMode) throw new Error('empty Go coverage profile');
  return truncated ? { files, sourceDirs: [], truncated } : { files, sourceDirs: [] };
}
