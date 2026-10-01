import { createReadStream, statSync } from 'node:fs';
import { createInterface } from 'node:readline';
import type { ParsedCoverage } from './lcov';
import { recordFor, type CoverageRecord } from './model';

/** `go test -coverprofile`'s first line (repeated when profiles are concatenated). */
export const GO_COVER_MODE = /^mode: (set|count|atomic)$/;
/** `<import path>/<file>.go:<line>.<col>,<line>.<col> <statements> <count>`. */
const BLOCK = /^(.+):(\d+)\.(\d+),(\d+)\.(\d+) (\d+) (\d+)$/;

/** The profile comes from the CI and is not trusted: a file this large is refused unread. */
export const MAX_GO_COVER_BYTES = 128 * 1024 * 1024;
/** A block this long (or one starting past the line limit) is not Go source; it is skipped. */
const MAX_BLOCK_LINES = 100_000;
const MAX_START_LINE = 10_000_000;
/** Lines claimed by all blocks together; stops a small file from costing minutes and gigabytes. */
const MAX_TOTAL_LINES = 5_000_000;

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
export async function parseGoCover(absPath: string): Promise<ParsedCoverage> {
  if (statSync(absPath).size > MAX_GO_COVER_BYTES) {
    throw new Error(`Go coverage profile too large (over ${MAX_GO_COVER_BYTES} bytes)`);
  }
  const files = new Map<string, CoverageRecord>();
  let sawMode = false;
  let claimed = 0;
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
    if (start < 1 || start > MAX_START_LINE || end - start >= MAX_BLOCK_LINES) continue;
    claimed += Math.max(end - start + 1, 0);
    if (claimed > MAX_TOTAL_LINES) throw new Error('Go coverage profile claims too many lines');
    const record = recordFor(files, file.startsWith('_/') ? file.slice(1) : file);
    for (let l = start; l <= end; l++) record.hit(l, Number(count));
  }
  if (!sawMode) throw new Error('empty Go coverage profile');
  return { files, sourceDirs: [] };
}
