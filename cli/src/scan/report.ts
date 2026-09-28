import { createWriteStream, mkdirSync, mkdtempSync, renameSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import {
  REDACTED,
  REPORT_BOUNDS,
  REPORT_SCHEMA_VERSION,
  reportSchema,
  type QualorConfig,
  type Report,
  type ReportFile,
} from '@qualor/shared';
import type { NormalizedEngines } from '../analyzers/normalize';
import { platformId } from '../commands/version';
import type { FileCoverage } from '../coverage/model';
import type { DuplicationGroup } from '../duplication/detect';
import { CliError, EXIT } from '../errors';
import type { ScmResolution } from '../git/scm';
import { VERSION } from '../index';
import type { Warnings } from '../warnings';
import type { AnalyzedFile } from './analyze-files';

export interface ReportParts {
  config: QualorConfig;
  projectKey: string;
  scm: ScmResolution;
  analysisDate: Date;
  files: readonly AnalyzedFile[];
  coverage: ReadonlyMap<string, FileCoverage>;
  duplications: DuplicationGroup[];
  engines: NormalizedEngines;
  warnings: Warnings;
}

/** report-format §3–§8 (findings, snippets and hashes come from the SARIF normaliser). */
export function assembleReport(p: ReportParts): Report {
  const newCode = p.scm.scm.baseline.status === 'ok';
  const files = p.files.map((a): ReportFile => {
    const entry: ReportFile = {
      path: a.file.path,
      language: a.file.language,
      kind: a.file.kind,
      sha256: a.sha256,
      lines: a.lines,
    };
    if (a.metrics !== undefined && a.file.language !== 'other') entry.metrics = a.metrics;
    const newLines = newCode ? p.scm.newLines(a.file.path) : undefined;
    if (newLines !== undefined) entry.newLines = newLines;
    const coverage = p.coverage.get(a.file.path);
    if (coverage !== undefined) entry.coverage = coverage;
    return entry;
  });
  // `git diff -M` covers the whole repository: only a rename onto a reported file can matter to
  // the server (issue tracking rewrites old paths through it), and the list is bounded (§9).
  const reported = new Set(files.map((f) => f.path));
  const onReported = p.scm.scm.renames.filter((r) => reported.has(r.to));
  const renames = onReported.slice(0, REPORT_BOUNDS.renames);
  if (onReported.length > renames.length) {
    p.warnings.add(
      'RENAMES_TRUNCATED',
      `${onReported.length - renames.length} of ${onReported.length} renames were dropped (at most ${REPORT_BOUNDS.renames} are reported); issues in those files may be tracked as new`,
    );
  }
  const { name, version } = p.config.project;
  const lastSegment =
    p.projectKey
      .split('/')
      .filter((s) => s !== '')
      .at(-1) ?? p.projectKey;
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    scanner: { name: 'qualor-cli', version: VERSION, platform: platformId() },
    project: {
      key: p.projectKey,
      name: name ?? lastSegment,
      ...(version !== undefined && version !== '' && { version }),
    },
    scm: { ...p.scm.scm, renames },
    analysisDate: p.analysisDate.toISOString(),
    engines: p.engines.engines,
    files,
    findings: p.engines.findings,
    duplications: p.duplications,
    warnings: p.warnings.list(),
  };
}

/** Secrets shorter than this are not scrubbed by value: too likely to match ordinary text. */
const MIN_SCRUBBED_SECRET_LENGTH = 8;

/**
 * Defence in depth (config.md §3.2): replaces every occurrence of a known secret value (the
 * resolved server token) with «redacted» in every string and object key of the report, whatever
 * path it took to get there (a config field, a file name, an analyzer message). Returns a copy.
 */
export function scrubSecretValues(report: Report, secrets: readonly (string | null)[]): Report {
  const values = secrets.filter(
    (s): s is string => s !== null && s.length >= MIN_SCRUBBED_SECRET_LENGTH,
  );
  if (values.length === 0) return report;
  const scrubString = (s: string): string =>
    values.reduce((acc, v) => acc.replaceAll(v, REDACTED), s);
  const scrub = (value: unknown): unknown => {
    if (typeof value === 'string') return scrubString(value);
    if (Array.isArray(value)) return value.map(scrub);
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [scrubString(k), scrub(v)]));
    }
    return value;
  };
  return scrub(report) as Report;
}

/**
 * scm.md §6: a rule id holding a secret an analyzer found (a custom rule named after a key, say)
 * has that secret replaced with «redacted», in the findings and in the engines' rule metadata
 * alike, so the rule keeps one key. The redaction of report-format.md §7 leaves rule ids alone
 * (a rule key is an identity), but a key reaches places no message does: Qualor's rule list,
 * GitLab's inline comments and GitLab's report files. The GitLab files scrub their copy the same
 * way, so a finding has one key everywhere. Returns the report itself when nothing changes.
 */
export function scrubRuleIds(report: Report, secrets: readonly string[]): Report {
  const values = [...new Set(secrets)]
    .filter((s) => s.length >= MIN_SCRUBBED_SECRET_LENGTH)
    .sort((a, b) => b.length - a.length);
  const scrub = (id: string) => values.reduce((acc, v) => acc.replaceAll(v, REDACTED), id);
  const touched =
    report.findings.some((f) => scrub(f.ruleId) !== f.ruleId) ||
    report.engines.some((e) => (e.rules ?? []).some((r) => scrub(r.id) !== r.id));
  if (!touched) return report;
  return {
    ...report,
    engines: report.engines.map((e) =>
      e.rules === undefined ? e : { ...e, rules: e.rules.map((r) => ({ ...r, id: scrub(r.id) })) },
    ),
    findings: report.findings.map((f) => ({ ...f, ruleId: scrub(f.ruleId) })),
  };
}

/** report-format §9: the CLI checks the server's bounds before uploading and exits 4. */
export function validateReport(candidate: Report): Report {
  const parsed = reportSchema.safeParse(candidate);
  if (parsed.success) return parsed.data;
  const issues = parsed.error.issues
    .slice(0, 5)
    .map((i) => `${i.path.join('.')}: ${i.message}`)
    .join('; ');
  throw new CliError(EXIT.SERVER, `the report does not match the report schema: ${issues}`);
}

/** Error codes that mean the `--output` path itself is unusable: the user's mistake (exit 2). */
const OUTPUT_PATH_ERRORS = new Set([
  'EISDIR',
  'EACCES',
  'ENOTDIR',
  'EEXIST',
  'EPERM',
  'ENOENT',
  'ENAMETOOLONG',
  'EROFS',
]);

/**
 * The containers serialised piece by piece: the root, its large arrays (report-format §9 bounds),
 * each engine and its `rules` (up to 20 000 per engine), and `scm` with its `renames`. Paths use
 * `[]` for "an element of".
 */
const STREAMED_PATHS = new Set([
  '',
  'files',
  'findings',
  'duplications',
  'engines',
  'engines[]',
  'engines[].rules',
  'scm',
  'scm.renames',
]);
/** Chunks are batched to about this many UTF-16 code units before they are handed to gzip. */
const CHUNK_CHARS = 64 * 1024;

/**
 * `JSON.stringify(value)` for a value at `path`, streamed where `STREAMED_PATHS` says so. Plain
 * objects and arrays only (a report is plain data): the same key order, the same omission of
 * `undefined`, functions and symbols in objects, and `null` for them in arrays.
 */
function* jsonPieces(value: unknown, path: string): Generator<string> {
  if (!STREAMED_PATHS.has(path) || value === null || typeof value !== 'object') {
    yield JSON.stringify(value) ?? 'null';
    return;
  }
  if (Array.isArray(value)) {
    yield '[';
    for (let i = 0; i < value.length; i++) {
      if (i > 0) yield ',';
      yield* jsonPieces(value[i], `${path}[]`);
    }
    yield ']';
    return;
  }
  yield '{';
  let first = true;
  for (const [key, child] of Object.entries(value)) {
    if (child === undefined || typeof child === 'function' || typeof child === 'symbol') continue;
    yield `${first ? '' : ','}${JSON.stringify(key)}:`;
    first = false;
    yield* jsonPieces(child, path === '' ? key : `${path}.${key}`);
  }
  yield '}';
}

/**
 * `JSON.stringify(report)`, in chunks: the large arrays are serialised one element at a time, so
 * a 500k-finding report (or 64 engines of 20 000 rules, or a long rename list) never exists as
 * one string. The concatenation is byte-for-byte `JSON.stringify(report)`.
 */
export function* reportJsonChunks(report: Report): Generator<string> {
  let buffer = '';
  for (const piece of jsonPieces(report, '')) {
    buffer += piece;
    if (buffer.length >= CHUNK_CHARS) {
      yield buffer;
      buffer = '';
    }
  }
  if (buffer !== '') yield buffer;
}

function removeQuietly(p: string): void {
  try {
    rmSync(p, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  } catch {
    // best effort: the path may be unusable for the same reason the write failed
  }
}

/**
 * Writes gzipped JSON through a temporary file, so a crash never leaves half a report behind.
 * The JSON is streamed through gzip (`reportJsonChunks`), never built as one string. A failure
 * removes the temporary file; a path problem (a directory, a path under a file, no permission)
 * exits 2, anything else exits 4 (ruling C14). Returns the compressed size. `mode` is the new
 * file's permission bits (before the umask).
 */
export async function writeReport(
  report: Report,
  outPath: string,
  o: { mode?: number } = {},
): Promise<number> {
  const partial = `${outPath}.${process.pid}.partial`;
  try {
    mkdirSync(path.dirname(outPath), { recursive: true });
    await pipeline(
      Readable.from(reportJsonChunks(report)),
      createGzip(),
      createWriteStream(partial, { mode: o.mode ?? 0o666 }),
    );
    renameSync(partial, outPath);
    return statSync(outPath).size;
  } catch (err) {
    removeQuietly(partial);
    const code = (err as NodeJS.ErrnoException).code;
    const reason = err instanceof Error ? err.message : String(err);
    throw new CliError(
      code !== undefined && OUTPUT_PATH_ERRORS.has(code) ? EXIT.USAGE : EXIT.SERVER,
      `cannot write the report to ${outPath}: ${reason}`,
    );
  }
}

/** The private report directories currently on disk (removed by the signal handler below). */
const privateDirs = new Set<string>();

/**
 * Removes every private report directory and exits with the conventional 128+signal code.
 * `process.exit()` does not unwind `withPrivateReportFile`'s `finally`, hence this handler.
 */
type CleanupSignal = 'SIGINT' | 'SIGTERM' | 'SIGHUP';
/** 128 + the signal number, as a shell reports it. */
const SIGNAL_EXIT: Record<CleanupSignal, number> = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };
/** SIGHUP (the terminal or CI runner went away) exists on POSIX only. */
const CLEANUP_SIGNALS: readonly CleanupSignal[] =
  process.platform === 'win32' ? ['SIGINT', 'SIGTERM'] : ['SIGINT', 'SIGTERM', 'SIGHUP'];

function onSignal(signal: CleanupSignal): void {
  for (const dir of privateDirs) removeQuietly(dir);
  privateDirs.clear();
  process.exit(SIGNAL_EXIT[signal]);
}

/**
 * Ruling E5: the report to upload, streamed through gzip into a private temporary file (a fresh
 * `mkdtemp` directory, mode 0700, holding `report.json.gz`, mode 0600), handed to `use`, and
 * removed afterwards on every path: success, a failed write, a failed `use`, and SIGINT, SIGTERM
 * and (POSIX) SIGHUP, exiting 130/143/129 (a handler is installed for exactly as long as the
 * directory exists). The report may hold finding snippets, so no other local user may read it.
 *
 * Windows: file modes are not enforced there (the ACL of the user's %TEMP% applies, which is
 * private to the user by default), and SIGTERM is never delivered (a killed process gets no
 * chance to clean up); Ctrl+C (SIGINT) is handled.
 */
export async function withPrivateReportFile<T>(
  report: Report,
  use: (f: { file: string; size: number }) => Promise<T>,
  o: { tempRoot?: string } = {},
): Promise<T> {
  const handlers = CLEANUP_SIGNALS.map((signal) => {
    const handler = () => onSignal(signal);
    process.on(signal, handler);
    return { signal, handler };
  });
  let dir: string | undefined;
  try {
    try {
      dir = mkdtempSync(path.join(o.tempRoot ?? os.tmpdir(), 'qualor-upload-'));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? 'unknown error';
      throw new CliError(
        EXIT.SERVER,
        `cannot create a temporary directory for the report: ${code}`,
      );
    }
    privateDirs.add(dir);
    const file = path.join(dir, 'report.json.gz');
    const size = await writeReport(report, file, { mode: 0o600 });
    return await use({ file, size });
  } finally {
    if (dir !== undefined) {
      removeQuietly(dir);
      privateDirs.delete(dir);
    }
    for (const { signal, handler } of handlers) process.removeListener(signal, handler);
  }
}
