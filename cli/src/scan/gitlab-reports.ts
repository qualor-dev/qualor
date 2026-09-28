import { randomBytes } from 'node:crypto';
import { lstatSync, realpathSync, renameSync, rmSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  DEPENDENCY_ENGINES,
  effectiveCwe,
  engineRuleDefaults,
  REDACTED,
  REPORT_BOUNDS,
  reportFingerprints,
  safeCodeSpan,
  safePlainValue,
  type Report,
  type Severity,
} from '@qualor/shared';
import { CliError, EXIT } from '../errors';

/** scm.md §9: the pinned version of GitLab's security report schemas (MIT, GitLab B.V.). */
export const SAST_SCHEMA_VERSION = '15.1.4';
export const SAST_SCHEMA_URL = `https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v${SAST_SCHEMA_VERSION}/dist/sast-report-format.json`;
/** scm.md §9 (plan 2B): the Dependency Scanning schema of the same release. */
export const DEPENDENCY_SCANNING_SCHEMA_URL = `https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v${SAST_SCHEMA_VERSION}/dist/dependency-scanning-report-format.json`;

/**
 * The secrets the analyzers found (report-format.md §7), for the free text of the report that the
 * CLI's redaction does not rewrite: rule names, and anything else copied into a GitLab file (rule
 * ids are already scrubbed in the report itself, scrubRuleIds; scrubbing again changes nothing). `unknown`: a secret engine's output could not be
 * read, so any rule name may hold a secret.
 */
export interface GitLabRedaction {
  texts: readonly string[];
  unknown: boolean;
}

export const NO_REDACTION: GitLabRedaction = { texts: [], unknown: false };

/** Texts shorter than this are not scrubbed: too likely to match ordinary text (as the report). */
const MIN_SCRUBBED_CHARS = 8;

function redactor(r: GitLabRedaction): {
  scrub: (s: string) => string;
  leaks: (s: string) => boolean;
} {
  const texts = [...new Set(r.texts)]
    .filter((t) => t.length >= MIN_SCRUBBED_CHARS)
    .sort((a, b) => b.length - a.length);
  const scrub = (s: string) => texts.reduce((acc, t) => acc.replaceAll(t, REDACTED), s);
  return { scrub, leaks: (s) => r.unknown || s.includes(REDACTED) || scrub(s) !== s };
}

/** Most severe first: the order entries are kept in when a file reaches its size bound. */
const SEVERITY_RANK: Record<Severity, number> = { blocker: 0, high: 1, medium: 2, low: 3, info: 4 };

/** A stable sort of `items` by the severity `of` each (blocker first); ties keep report order. */
function bySeverity<T>(items: readonly T[], of: (item: T) => Severity): T[] {
  return items
    .map((item, index) => ({ item, index, rank: SEVERITY_RANK[of(item)] }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index)
    .map((x) => x.item);
}

/**
 * GitLab's Code Quality report (scm.md §9): the Code Climate subset GitLab reads for the merge
 * request widget and the pipeline's Code Quality tab.
 */
export interface CodeQualityEntry {
  description: string;
  check_name: string;
  fingerprint: string;
  severity: 'info' | 'minor' | 'major' | 'critical' | 'blocker';
  location: { path: string; lines: { begin: number } };
}

const CODE_QUALITY_SEVERITY: Record<Severity, CodeQualityEntry['severity']> = {
  blocker: 'blocker',
  high: 'critical',
  medium: 'major',
  low: 'minor',
  info: 'info',
};

/**
 * Every finding with a location, from the final report (after every redaction and the token
 * scrub), so nothing a report may not carry reaches the file; the rule key is scrubbed of the
 * analyzers' secrets too. `fingerprint` is the value the server computes (data-model.md §5.1). A
 * finding without its own severity takes its rule's default, else `medium` (report-format.md
 * §7.1). Most severe first, so the size bound drops the least severe.
 */
export function codeQualityReport(
  report: Report,
  redaction: GitLabRedaction = NO_REDACTION,
): CodeQualityEntry[] {
  const { scrub } = redactor(redaction);
  const fingerprints = reportFingerprints(report.findings);
  const defaults = new Map<string, Severity>();
  for (const engine of report.engines) {
    for (const rule of engine.rules) {
      if (rule.defaultSeverity) defaults.set(`${engine.id}:${rule.id}`, rule.defaultSeverity);
    }
  }
  const entries: { entry: CodeQualityEntry; severity: Severity }[] = [];
  report.findings.forEach((finding, index) => {
    if (finding.location === null) return;
    const key = `${finding.engineId}:${finding.ruleId}`;
    const severity = finding.severity ?? defaults.get(key) ?? 'medium';
    entries.push({
      severity,
      entry: {
        description: finding.message,
        check_name: scrub(key),
        fingerprint: fingerprints[index] ?? '',
        severity: CODE_QUALITY_SEVERITY[severity],
        location: { path: finding.location.path, lines: { begin: finding.location.startLine } },
      },
    });
  });
  return bySeverity(entries, (e) => e.severity).map((e) => e.entry);
}

interface SastIdentifier {
  type: string;
  name: string;
  value: string;
  url?: string;
}

export interface SastVulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  identifiers: SastIdentifier[];
  location: { file: string; start_line: number; end_line: number };
}

export interface SastReport {
  version: string;
  schema: string;
  scan: {
    type: 'sast';
    status: 'success' | 'failure';
    start_time: string;
    end_time: string;
    analyzer: { id: string; name: string; version: string; vendor: { name: string } };
    scanner: { id: string; name: string; version: string; vendor: { name: string } };
    messages?: { level: 'info' | 'warn' | 'fatal'; value: string }[];
  };
  vulnerabilities: SastVulnerability[];
}

const SAST_SEVERITY: Record<Severity, SastVulnerability['severity']> = {
  blocker: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};
/** The schema's `name` bound, in characters. */
const MAX_NAME_CHARS = 255;

/** `2026-09-22T10:15:00`: the schema's time format (UTC, no fraction, no zone). */
export function sastTime(date: Date): string {
  return date.toISOString().slice(0, 19);
}

/** A 32-hex fingerprint laid out as a UUID, the form GitLab shows vulnerability ids in. */
function fingerprintId(fingerprint: string): string {
  const f = fingerprint.padEnd(32, '0');
  return `${f.slice(0, 8)}-${f.slice(8, 12)}-${f.slice(12, 16)}-${f.slice(16, 20)}-${f.slice(20, 32)}`;
}

export interface SastOptions {
  redaction?: GitLabRedaction;
  /**
   * Ruling G6: the engines that did not complete (failed, timed out, or unavailable: the tool
   * could not run here). Any makes the scan a `failure`, so GitLab does not take the missing
   * findings of such an engine as fixed.
   */
  incomplete?: readonly string[];
}

/**
 * GitLab's SAST report, schema {@link SAST_SCHEMA_VERSION} (scm.md §9): one vulnerability per
 * located finding whose rule's quality is `security` (its metadata in `engines[].rules`, else the
 * engine default of report-format.md §7.1), most severe first. Built from the final report, like
 * the Code Quality report; no source extract, snippet, link or solution is written, so no
 * report-controlled text becomes a link and no source code leaves the job. The description is a
 * scm.md §6 code span (GitLab renders it as Markdown); a rule name that holds a secret, or any
 * name while the secrets are unknown, gives way to the (scrubbed) rule key.
 */
export function sastReport(
  report: Report,
  times: { start: Date; end: Date },
  o: SastOptions = {},
): SastReport {
  const { scrub, leaks } = redactor(o.redaction ?? NO_REDACTION);
  const fingerprints = reportFingerprints(report.findings);
  const rules = new Map<
    string,
    { name?: string | undefined; quality?: string | undefined; cwe: readonly number[] }
  >();
  for (const engine of report.engines) {
    for (const rule of engine.rules) {
      rules.set(`${engine.id}:${rule.id}`, {
        name: rule.name,
        quality: rule.quality,
        cwe: rule.cwe ?? [],
      });
    }
  }
  const found: { vulnerability: SastVulnerability; severity: Severity }[] = [];
  report.findings.forEach((finding, index) => {
    if (finding.location === null) return;
    if (DEPENDENCY_ENGINES.has(finding.engineId)) return;
    const key = `${finding.engineId}:${finding.ruleId}`;
    const rule = rules.get(key);
    const defaults = engineRuleDefaults(finding.engineId);
    if ((rule?.quality ?? defaults.quality) !== 'security') return;
    const cwe = effectiveCwe({ key, engineId: finding.engineId, cwe: rule?.cwe ?? [] });
    const safeKey = scrub(key);
    const ruleName = rule?.name?.trim() ?? '';
    const name = safePlainValue(
      ruleName !== '' && !leaks(ruleName) ? ruleName : safeKey,
      MAX_NAME_CHARS,
    );
    const severity = finding.severity ?? defaults.defaultSeverity;
    found.push({
      severity,
      vulnerability: {
        id: fingerprintId(fingerprints[index] ?? ''),
        name,
        description: safeCodeSpan(finding.message, REPORT_BOUNDS.messageChars),
        severity: SAST_SEVERITY[severity],
        identifiers: [
          { type: 'qualor_rule', name: safeKey, value: safeKey },
          ...cwe.map((n) => ({
            type: 'cwe',
            name: `CWE-${n}`,
            value: String(n),
            url: `https://cwe.mitre.org/data/definitions/${n}.html`,
          })),
        ],
        location: {
          file: finding.location.path,
          start_line: finding.location.startLine,
          end_line: finding.location.endLine ?? finding.location.startLine,
        },
      },
    });
  });
  return {
    version: SAST_SCHEMA_VERSION,
    schema: SAST_SCHEMA_URL,
    scan: { type: 'sast', ...scanHeader(report, times, o.incomplete ?? []) },
    vulnerabilities: bySeverity(found, (v) => v.severity).map((v) => v.vulnerability),
  };
}

type ScanMessage = { level: 'info' | 'warn' | 'fatal'; value: string };

/**
 * The `scan` object of GitLab's security reports, but its `type`: Qualor as analyzer and scanner,
 * and ruling G6's `failure` (with a `warn` message) when an engine did not complete or, for
 * Dependency Scanning, when a finding could not be written (`problems`).
 */
function scanHeader(
  report: Report,
  times: { start: Date; end: Date },
  incomplete: readonly string[],
  problems: readonly string[] = [],
): Omit<SastReport['scan'], 'type'> {
  const tool = {
    id: 'qualor',
    name: 'Qualor',
    version: report.scanner.version,
    vendor: { name: 'Qualor' },
  };
  const messages: ScanMessage[] = [
    ...(incomplete.length > 0
      ? [
          {
            level: 'warn' as const,
            value: `not every analyzer completed (${incomplete.join(', ')}): findings they would report are missing, not fixed`,
          },
        ]
      : []),
    ...problems.map((value) => ({ level: 'warn' as const, value })),
  ];
  return {
    status: messages.length > 0 ? 'failure' : 'success',
    start_time: sastTime(times.start),
    end_time: sastTime(times.end),
    analyzer: tool,
    scanner: tool,
    ...(messages.length > 0 && { messages }),
  };
}

export interface DependencyScanningVulnerability {
  id: string;
  name: string;
  description: string;
  severity: SastVulnerability['severity'];
  identifiers: SastIdentifier[];
  location: {
    file: string;
    dependency: { package: { name: string }; version: string; direct?: boolean };
  };
}

export interface DependencyScanningReport {
  version: string;
  schema: string;
  scan: Omit<SastReport['scan'], 'type'> & { type: 'dependency_scanning' };
  vulnerabilities: DependencyScanningVulnerability[];
}

/** A vulnerability id's identifier type: GitLab links `cve` and `ghsa` identifiers itself. */
function vulnerabilityIdType(id: string): string {
  if (/^CVE-\d{4}-\d{4,}$/.test(id)) return 'cve';
  if (/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/.test(id)) return 'ghsa';
  return 'qualor_rule';
}

/** The package a dependency finding names (report-format.md §7.1 `properties.dependency`). */
/**
 * The located findings of a dependency engine that name no package (their properties were
 * dropped): the Dependency Scanning file leaves them out and is a `failure` (scm.md §9).
 */
export function unnamedDependencyFindings(report: Report): number {
  return report.findings.filter(
    (f) => f.location !== null && DEPENDENCY_ENGINES.has(f.engineId) && dependencyOf(f) === null,
  ).length;
}

function dependencyOf(
  finding: Report['findings'][number],
): { name: string; version: string; direct: boolean } | null {
  const d = finding.properties?.['dependency'];
  if (typeof d !== 'object' || d === null) return null;
  const { name, version, direct } = d as { name?: unknown; version?: unknown; direct?: unknown };
  if (typeof name !== 'string' || name.trim() === '') return null;
  if (typeof version !== 'string' || version.trim() === '') return null;
  return { name, version, direct: direct === true };
}

/**
 * GitLab's Dependency Scanning report, schema {@link SAST_SCHEMA_VERSION} (scm.md §9, plan 2B):
 * one vulnerability per located finding of a dependency engine (Trivy), in its lockfile, with the
 * package and version from the finding's properties; most severe first. Built from the final
 * report like the SAST file, with the same safety: no links but the CWE's, no solution or source,
 * the description a code span, the names plain values. A finding without its package is left
 * out and makes the scan a `failure` (GitLab would take the missing vulnerability as fixed).
 */
export function dependencyScanningReport(
  report: Report,
  times: { start: Date; end: Date },
  o: SastOptions = {},
): DependencyScanningReport {
  const { scrub } = redactor(o.redaction ?? NO_REDACTION);
  const fingerprints = reportFingerprints(report.findings);
  const cwes = new Map<string, readonly number[]>();
  for (const engine of report.engines) {
    for (const rule of engine.rules) cwes.set(`${engine.id}:${rule.id}`, rule.cwe ?? []);
  }
  const found: { vulnerability: DependencyScanningVulnerability; severity: Severity }[] = [];
  report.findings.forEach((finding, index) => {
    if (finding.location === null || !DEPENDENCY_ENGINES.has(finding.engineId)) return;
    const dependency = dependencyOf(finding);
    if (dependency === null) return;
    const key = `${finding.engineId}:${finding.ruleId}`;
    const safeKey = scrub(key);
    const id = safePlainValue(scrub(finding.ruleId), MAX_NAME_CHARS);
    const cwe = effectiveCwe({ key, engineId: finding.engineId, cwe: cwes.get(key) ?? [] });
    const severity = finding.severity ?? engineRuleDefaults(finding.engineId).defaultSeverity;
    found.push({
      severity,
      vulnerability: {
        id: fingerprintId(fingerprints[index] ?? ''),
        name: id,
        description: safeCodeSpan(finding.message, REPORT_BOUNDS.messageChars),
        severity: SAST_SEVERITY[severity],
        identifiers: [
          { type: vulnerabilityIdType(id), name: id, value: id },
          { type: 'qualor_rule', name: safeKey, value: safeKey },
          ...cwe.map((n) => ({
            type: 'cwe',
            name: `CWE-${n}`,
            value: String(n),
            url: `https://cwe.mitre.org/data/definitions/${n}.html`,
          })),
        ],
        location: {
          file: finding.location.path,
          dependency: {
            package: { name: safePlainValue(scrub(dependency.name), MAX_NAME_CHARS) },
            version: safePlainValue(scrub(dependency.version), MAX_NAME_CHARS),
            ...(dependency.direct && { direct: true }),
          },
        },
      },
    });
  });
  const unnamed = unnamedDependencyFindings(report);
  const problems =
    unnamed > 0
      ? [
          `${unnamed} dependency finding(s) could not be written without their package: they are missing, not fixed`,
        ]
      : [];
  return {
    version: SAST_SCHEMA_VERSION,
    schema: DEPENDENCY_SCANNING_SCHEMA_URL,
    scan: {
      type: 'dependency_scanning',
      ...scanHeader(report, times, o.incomplete ?? [], problems),
    },
    vulnerabilities: bySeverity(found, (v) => v.severity).map((v) => v.vulnerability),
  };
}

/**
 * scm.md §9: the most a GitLab report file may hold. GitLab parses each file whole, in memory, for
 * the merge request widget; past this size the last (least severe) entries are left out, with a
 * warning, so a run with an enormous number of findings still produces a file GitLab accepts.
 */
export const MAX_GITLAB_REPORT_BYTES = 32 * 1024 * 1024;

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}

/**
 * scm.md §9: a `--gitlab-*` file is written in the working directory (the checkout, in CI) and
 * must be writable where it is asked for; checked before any analyzer runs, so a typo costs
 * nothing, and again just before the write. Its directory must exist and, links resolved, lie in
 * the working directory; the file itself must not be a directory or a symbolic link (a link is
 * never followed, wherever it points). Returns the path to write, its directory resolved.
 */
export function checkReportPath(flag: string, cwd: string, file: string): string {
  const fail = (why: string): never => {
    throw new CliError(EXIT.USAGE, `--${flag} ${file}: ${why}`);
  };
  const target = path.resolve(cwd, file);
  let dir: string;
  try {
    dir = realpathSync.native(path.dirname(target));
  } catch {
    return fail('its directory does not exist');
  }
  let root: string;
  try {
    root = realpathSync.native(cwd);
  } catch {
    root = path.resolve(cwd);
  }
  if (!isInside(root, dir)) fail('is outside the working directory');
  const resolved = path.join(dir, path.basename(target));
  let stats;
  try {
    stats = lstatSync(resolved);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return resolved;
    if (code === 'ENOTDIR') return fail('its directory is not a directory');
    return fail(`cannot be checked (${code ?? 'unknown error'})`);
  }
  if (stats.isSymbolicLink()) fail('is a symbolic link');
  if (stats.isDirectory()) fail('is a directory');
  if (!stats.isFile()) fail('is not a regular file');
  return resolved;
}

/**
 * `JSON.stringify(wrap(items))` with a final newline, keeping as many whole items (from the start)
 * as fit in `maxBytes` of UTF-8. The file stays valid JSON whatever is left out.
 */
export function boundedJson<T>(
  items: readonly T[],
  wrap: (kept: T[]) => unknown,
  maxBytes: number,
): { text: string; kept: number } {
  let total = Buffer.byteLength(JSON.stringify(wrap([]))) + 1;
  if (total > maxBytes)
    throw new Error(`internal error: an empty report exceeds ${maxBytes} bytes`);
  let kept = 0;
  for (const item of items) {
    const size = Buffer.byteLength(JSON.stringify(item)) + (kept > 0 ? 1 : 0);
    if (total + size > maxBytes) break;
    total += size;
    kept += 1;
  }
  return { text: `${JSON.stringify(wrap(items.slice(0, kept)))}\n`, kept };
}

/** Error codes that mean the path itself is unusable: the user's mistake (exit 2, as --output). */
const PATH_ERRORS = new Set([
  'EISDIR',
  'EACCES',
  'ENOTDIR',
  'EEXIST',
  'EPERM',
  'ENOENT',
  'ENAMETOOLONG',
  'EROFS',
]);

export interface WrittenReport {
  target: string;
  bytes: number;
  kept: number;
  dropped: number;
}

/**
 * Writes a GitLab report file atomically: the path is checked again (a link placed since the first
 * check is refused), the JSON goes to a fresh temporary file next to it (created exclusively, so
 * never through an existing link), which is then renamed over the target (a rename replaces a
 * directory entry, it never follows a link). The size is bounded by {@link boundedJson}.
 */
export async function writeGitLabReport<T>(
  flag: string,
  cwd: string,
  file: string,
  items: readonly T[],
  wrap: (kept: T[]) => unknown,
  maxBytes: number = MAX_GITLAB_REPORT_BYTES,
): Promise<WrittenReport> {
  const target = checkReportPath(flag, cwd, file);
  const { text, kept } = boundedJson(items, wrap, maxBytes);
  const partial = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${randomBytes(6).toString('hex')}.partial`,
  );
  try {
    await writeFile(partial, text, { encoding: 'utf8', flag: 'wx', mode: 0o644 });
    renameSync(partial, target);
  } catch (err) {
    rmSync(partial, { force: true });
    const code = (err as NodeJS.ErrnoException).code ?? 'unknown error';
    throw new CliError(
      PATH_ERRORS.has(code) ? EXIT.USAGE : EXIT.SERVER,
      `--${flag} ${file}: cannot be written (${code})`,
    );
  }
  return { target, bytes: Buffer.byteLength(text), kept, dropped: items.length - kept };
}
