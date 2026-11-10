import { closeSync, existsSync, openSync, readdirSync, readSync, statSync } from 'node:fs';
import path from 'node:path';
import { normalizeRepoPath } from '@qualor/shared';
import picomatch from 'picomatch';
import type { Logger } from '../log';
import type { Warnings } from '../warnings';
import { parseCobertura } from './cobertura';
import { GO_COVER_MODE, parseGoCover } from './gocover';
import { parseJacoco } from './jacoco';
import { parseLcov, type ParsedCoverage } from './lcov';
import { CoverageAccumulator, type FileCoverage } from './model';
import { ancestorDirs, PathResolver, repoRelativeDir } from './resolve';

/** `gocover`: the Go coverage profile (plan 9C). */
export type CoverageFormat = 'lcov' | 'cobertura' | 'jacoco' | 'gocover';

const COVERAGE_PARSERS: Partial<
  Record<CoverageFormat, (absPath: string) => Promise<ParsedCoverage>>
> = {
  lcov: parseLcov,
  cobertura: parseCobertura,
  jacoco: parseJacoco,
  gocover: parseGoCover,
};

export interface CoverageTarget {
  path: string;
  kind: 'main' | 'test';
  lines: number;
}

export interface ImportCoverageOptions {
  root: string;
  reports: readonly { path: string; format: 'auto' | CoverageFormat }[];
  files: readonly CoverageTarget[];
  pathPrefixes: readonly string[];
  warnings: Warnings;
  log: Logger;
}

const GLOB = /[*?[\]{}]/;
const SKIPPED_DIRS = new Set(['.git', 'node_modules']);

/** A literal path (relative to the root, or absolute), or a glob searched below the root. */
export function expandReportPaths(root: string, pattern: string): string[] {
  const normalized = pattern.replaceAll('\\', '/');
  if (!GLOB.test(normalized)) {
    const abs = path.resolve(root, normalized);
    return existsSync(abs) && statSync(abs).isFile() ? [abs] : [];
  }
  const match = picomatch(normalized.replace(/^\.\//, ''), { dot: true });
  const out: string[] = [];
  const pending: ReportDir[] = [{ abs: root, rel: '' }];
  for (let dir = pending.pop(); dir !== undefined; dir = pending.pop()) {
    searchReportDir(dir, match, pending, out);
  }
  return out.sort();
}

interface ReportDir {
  abs: string;
  rel: string;
}

/** Queues a directory's subdirectories (not `.git`, `node_modules`), collects matching files. */
function searchReportDir(
  dir: ReportDir,
  match: (rel: string) => boolean,
  pending: ReportDir[],
  out: string[],
): void {
  let entries;
  try {
    entries = readdirSync(dir.abs, { withFileTypes: true });
  } catch {
    return; // unreadable directories simply contain no reports
  }
  for (const entry of entries) {
    const rel = dir.rel === '' ? entry.name : `${dir.rel}/${entry.name}`;
    if (entry.isDirectory() && !SKIPPED_DIRS.has(entry.name)) {
      pending.push({ abs: path.join(dir.abs, entry.name), rel });
    } else if (entry.isFile() && match(rel)) out.push(path.join(dir.abs, entry.name));
  }
}

function head(absPath: string, bytes: number): string {
  const fd = openSync(absPath, 'r');
  try {
    const buffer = Buffer.alloc(bytes);
    const read = readSync(fd, buffer, 0, bytes, 0);
    return buffer.subarray(0, read).toString('utf8');
  } finally {
    closeSync(fd);
  }
}

const BOM_CODE_POINT = 0xfeff;

export function detectFormat(absPath: string): CoverageFormat | null {
  let raw = head(absPath, 4096);
  if (raw.charCodeAt(0) === BOM_CODE_POINT) raw = raw.slice(1);
  const text = raw.trimStart();
  if (GO_COVER_MODE.test(text.split(/\r?\n/, 1)[0]?.trim() ?? '')) return 'gocover';
  if (/^(TN|SF):/m.test(text)) return 'lcov';
  if (text.startsWith('<')) {
    if (/<coverage[\s>]/.test(text)) return 'cobertura';
    if (/<report[\s>]/.test(text)) return 'jacoco';
  }
  return null;
}

function sourceDirToRepo(root: string, dir: string): string | null {
  const d = dir.trim().replaceAll('\\', '/');
  if (d === '' || d === '.' || d === './') return '';
  const absolute = d.startsWith('/') || /^[A-Za-z]:\//.test(d);
  try {
    return normalizeRepoPath(d, absolute ? root : undefined);
  } catch {
    return null; // a build machine's directory outside this checkout
  }
}

/** Imports every configured report and returns coverage per analysed main file (ruling C12). */
export async function importCoverage(o: ImportCoverageOptions): Promise<Map<string, FileCoverage>> {
  const targets = new Map(o.files.map((f) => [f.path, f]));
  const resolver = new PathResolver(o.root, targets.keys(), o.pathPrefixes);
  const run: ImportRun = { o, targets, resolver, acc: new CoverageAccumulator() };
  for (const spec of o.reports) {
    const matches = expandReportPaths(o.root, spec.path);
    if (matches.length === 0) {
      o.warnings.add('COVERAGE_REPORT_NOT_FOUND', `no coverage report matched ${spec.path}`);
      continue;
    }
    for (const abs of matches) {
      const parsed = await parseReport(o, spec.format, abs);
      if (parsed !== null) addReport(run, abs, parsed);
    }
  }
  return coverageByFile(run);
}

/** What every report of one import adds to. */
interface ImportRun {
  o: ImportCoverageOptions;
  targets: ReadonlyMap<string, CoverageTarget>;
  resolver: PathResolver;
  acc: CoverageAccumulator;
}

/** One report, parsed in its format (detected under `auto`); null, with a warning, if unusable. */
async function parseReport(o: ImportCoverageOptions, specFormat: 'auto' | CoverageFormat, abs: string): Promise<ParsedCoverage | null> {
  const format = specFormat === 'auto' ? detectFormat(abs) : specFormat;
  if (format === null) {
    o.warnings.add('COVERAGE_FORMAT_UNKNOWN', 'a coverage report was not LCOV, Cobertura, JaCoCo or a Go coverage profile');
    return null;
  }
  const parse = COVERAGE_PARSERS[format];
  if (parse === undefined) {
    o.warnings.add('COVERAGE_FORMAT_UNSUPPORTED', `${format} coverage reports are not supported yet`);
    return null;
  }
  try {
    return await parse(abs);
  } catch (err) {
    o.warnings.add('COVERAGE_REPORT_INVALID', 'a coverage report could not be parsed and was ignored');
    o.log.warn(`cannot parse coverage report ${abs}: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

/** Adds a report's records of analysed main files; entries placed nowhere are warned about. */
function addReport(run: ImportRun, abs: string, parsed: ParsedCoverage): void {
  const { o } = run;
  if (parsed.truncated === true) {
    o.warnings.add('COVERAGE_REPORT_TRUNCATED', 'a coverage report was too large; the part past the limit was ignored');
  }
  const baseDirs = [
    ...parsed.sourceDirs.map((d) => sourceDirToRepo(o.root, d)).filter((d): d is string => d !== null),
    ...ancestorDirs(repoRelativeDir(o.root, abs)),
  ];
  let unresolved = 0;
  let ambiguous = 0;
  for (const [reportPath, record] of parsed.files) {
    const r = run.resolver.resolve(reportPath, baseDirs);
    if ('unresolved' in r) {
      if (r.unresolved === 'ambiguous') ambiguous++;
      else unresolved++;
    } else if (run.targets.get(r.path)?.kind === 'main') run.acc.add(r.path, record);
  }
  if (unresolved > 0) {
    o.warnings.add('COVERAGE_PATH_UNRESOLVED', 'coverage entries whose path matches no analysed file were ignored', unresolved);
  }
  if (ambiguous > 0) {
    o.warnings.add('COVERAGE_PATH_AMBIGUOUS', 'coverage entries matching several files were ignored', ambiguous);
  }
}

/** The coverage per analysed main file; lines past a file's end are counted in a warning. */
function coverageByFile({ o, targets, acc }: ImportRun): Map<string, FileCoverage> {
  const out = new Map<string, FileCoverage>();
  let outOfRange = 0;
  for (const p of acc.paths()) {
    const target = targets.get(p);
    const result = target === undefined ? undefined : acc.toFileCoverage(p, target.lines);
    if (result === undefined) continue;
    outOfRange += result.outOfRange;
    out.set(p, result.coverage);
  }
  if (outOfRange > 0) {
    o.warnings.add('COVERAGE_LINE_OUT_OF_RANGE', 'coverage for lines past the end of a file was ignored (stale report?)', outOfRange);
  }
  return out;
}
