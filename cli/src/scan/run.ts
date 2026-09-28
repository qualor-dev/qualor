import path from 'node:path';
import type { Report } from '@qualor/shared';
import { loadExternalSarif } from '../analyzers/external';
import { fileLines, normalizeCaptures } from '../analyzers/normalize';
import { builtinAnalyzers } from '../analyzers/registry';
import { requiredFailures, runAnalyzers } from '../analyzers/runner';
import type { Analyzer, DotnetRun } from '../analyzers/types';
import type { ScanFlags } from '../args';
import { loadSettings, requireServer, type Settings } from '../config/settings';
import { importCoverage } from '../coverage/import';
import { discoverFiles } from '../discovery/discover';
import { detectDuplications } from '../duplication/detect';
import { CliError, EXIT, type ExitCode } from '../errors';
import { createGit, type Git } from '../git/git';
import { resolveScm } from '../git/scm';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { loadParsers, type Parsers } from '../parse/grammars';
import { httpBaselineClient, type NewCodeBaselineClient } from '../server/baseline-client';
import { serverEndpoint } from '../server/endpoint';
import { describeGate, gateExitCode, waitForAnalysis } from '../server/gate';
import type { ServerEndpoint } from '../server/http';
import { uploadReport } from '../server/upload';
import { Warnings } from '../warnings';
import {
  analyzeFiles,
  duplicationFilter,
  duplicationInputs,
  type AnalyzedFile,
} from './analyze-files';
import {
  checkReportPath,
  codeQualityReport,
  dependencyScanningReport,
  unnamedDependencyFindings,
  MAX_GITLAB_REPORT_BYTES,
  sastReport,
  writeGitLabReport,
  type GitLabRedaction,
  type WrittenReport,
} from './gitlab-reports';
import {
  assembleReport,
  scrubRuleIds,
  scrubSecretValues,
  validateReport,
  withPrivateReportFile,
  writeReport,
} from './report';

export interface ScanDeps {
  parsers?: Parsers;
  analyzers?: readonly Analyzer[];
  /** undefined: an HTTP client when a trusted URL and a token are configured; null: no server. */
  baselineClient?: NewCodeBaselineClient | null;
  git?: Git;
  now?: () => Date;
  /** Pauses between upload retries and gate polls (tests replace the timer). */
  wait?: (ms: number) => Promise<unknown>;
  /** The clock of the gate deadline (tests move it). */
  clock?: () => number;
  /** `qualor dotnet end`'s logs (config.md §6.1); absent or null in a plain `qualor scan`. */
  dotnet?: DotnetRun | null;
  /** `qualor dotnet end`'s own warnings (config.md §6.1), added to the report's `warnings`. */
  extraWarnings?: readonly { code: string; message: string }[];
}

interface BuiltReport {
  report: Report;
  /** Required analyzers that failed or timed out (config.md §7 exit 3). */
  failed: string[];
  /** What the GitLab report files need beyond the report (scm.md §9, ruling G6). */
  gitlab: GitLabContext;
}

interface GitLabContext {
  redaction: GitLabRedaction;
  /**
   * Ruling G6: engines that did not complete: failed, timed out, or unavailable (the tool could
   * not run here). A configuration skip or a disabled analyzer is complete.
   */
  incomplete: string[];
}

async function buildReport(
  settings: Settings,
  flags: ScanFlags,
  projectKey: string,
  endpoint: ServerEndpoint | null,
  analyzers: readonly Analyzer[],
  io: CliIO,
  log: Logger,
  deps: ScanDeps,
): Promise<BuiltReport> {
  const { root, config } = settings;
  const analysisDate = (deps.now ?? (() => new Date()))();
  const warnings = new Warnings();
  for (const w of deps.extraWarnings ?? []) warnings.add(w.code, w.message);

  // Fail fast on a bad --sarif file: a usage error must come before any git or network call.
  const external = loadExternalSarif(config.sarif, { root, warnings });

  const baselineClient =
    deps.baselineClient !== undefined
      ? deps.baselineClient
      : endpoint === null
        ? null
        : httpBaselineClient(endpoint, log);
  const scm = await resolveScm({
    git: deps.git ?? createGit(root, io.env),
    settings,
    flags,
    baselineClient,
    warnings,
    log,
  });

  const scope = discoverFiles({ root, config, warnings, log });
  const parsers = deps.parsers ?? (await loadParsers());
  let analyzed: AnalyzedFile[];
  try {
    analyzed = analyzeFiles(scope, {
      parsers,
      warnings,
      log,
      collectUnits: duplicationFilter(config),
    });
  } finally {
    if (deps.parsers === undefined) parsers.delete();
  }
  const duplications = detectDuplications(duplicationInputs(analyzed), config.duplication);
  const coverage = await importCoverage({
    root,
    reports: config.coverage.reports,
    files: analyzed.map((a) => ({ path: a.file.path, kind: a.file.kind, lines: a.lines })),
    pathPrefixes: config.coverage.pathPrefixes,
    warnings,
    log,
  });
  const files = analyzed.map((a) => a.file);
  const captures = [
    ...(await runAnalyzers(analyzers, {
      root,
      config,
      files,
      log,
      env: io.env,
      dotnet: deps.dotnet ?? null,
    })),
    ...external,
  ];
  let redaction: GitLabRedaction = { texts: [], unknown: false };
  const engines = normalizeCaptures(captures, {
    repoRoot: root,
    readLines: fileLines(root),
    knownPaths: new Set(files.map((f) => f.path)),
    log,
    onSecrets: (texts, unknown) => {
      redaction = { texts, unknown };
    },
  });
  warnings.addAll(engines.warnings);

  const report = validateReport(
    scrubRuleIds(
      scrubSecretValues(
        assembleReport({
          config,
          projectKey,
          scm,
          analysisDate,
          files: analyzed,
          coverage,
          duplications,
          engines,
          warnings,
        }),
        [settings.token],
      ),
      redaction.texts,
    ),
  );
  const unavailable = new Set(
    captures.filter((c) => c.unavailable === true).map((c) => c.engineId),
  );
  return {
    report,
    failed: requiredFailures(captures, report.engines),
    gitlab: {
      redaction,
      incomplete: report.engines
        .filter((e) => e.status === 'failed' || e.status === 'timeout' || unavailable.has(e.id))
        .map((e) => e.id),
    },
  };
}

/**
 * scm.md §9: GitLab's report files, from the final report (redacted and scrubbed), written before
 * the upload so they exist whatever the gate says (the CI component keeps them `when: always`).
 * Ruling G6: when an engine did not complete, the Code Quality file is not written (GitLab would
 * show that engine's findings as fixed) and the SAST and Dependency Scanning scans are a
 * `failure`. A file that cannot be
 * written now (the path was checked before the scan) is a warning: the analysis still uploads.
 */
async function writeGitLabReports(
  flags: ScanFlags,
  report: Report,
  gitlab: GitLabContext,
  io: CliIO,
  log: Logger,
  now: () => Date,
): Promise<void> {
  const incomplete = gitlab.incomplete.join(', ');
  const attempt = async (flag: string, write: () => Promise<void>) => {
    try {
      await write();
    } catch (err) {
      if (!(err instanceof CliError)) throw err;
      log.warn(`${err.message}; the analysis goes on without it`);
    }
  };
  const written = (flag: string, what: string, w: WrittenReport) => {
    log.info(`wrote ${w.target} (${w.kept} ${what})`);
    if (w.dropped > 0) {
      log.warn(
        `--${flag}: ${w.dropped} of ${w.kept + w.dropped} ${what} left out: the file is capped at ${MAX_GITLAB_REPORT_BYTES} bytes`,
      );
    }
  };
  const codeQualityFile = flags.gitlabCodeQuality;
  if (codeQualityFile !== undefined) {
    const flag = 'gitlab-code-quality';
    if (gitlab.incomplete.length > 0) {
      log.warn(
        `--${flag}: not written, because not every analyzer completed (${incomplete}): GitLab would show their findings as fixed`,
      );
    } else {
      await attempt(flag, async () => {
        const w = await writeGitLabReport(
          flag,
          io.cwd,
          codeQualityFile,
          codeQualityReport(report, gitlab.redaction),
          (kept) => kept,
        );
        written(flag, 'Code Quality entries', w);
      });
    }
  }
  const sastFile = flags.gitlabSast;
  if (sastFile !== undefined) {
    const flag = 'gitlab-sast';
    if (gitlab.incomplete.length > 0) {
      log.warn(
        `--${flag}: the scan is marked failed, because not every analyzer completed (${incomplete})`,
      );
    }
    await attempt(flag, async () => {
      const sast = sastReport(
        report,
        { start: new Date(report.analysisDate), end: now() },
        { redaction: gitlab.redaction, incomplete: gitlab.incomplete },
      );
      const w = await writeGitLabReport(
        flag,
        io.cwd,
        sastFile,
        sast.vulnerabilities,
        (vulnerabilities) => ({ ...sast, vulnerabilities }),
      );
      written(flag, 'SAST vulnerabilities', w);
    });
  }
  const dependencyFile = flags.gitlabDependencyScanning;
  if (dependencyFile !== undefined) {
    const flag = 'gitlab-dependency-scanning';
    if (gitlab.incomplete.length > 0) {
      log.warn(
        `--${flag}: the scan is marked failed, because not every analyzer completed (${incomplete})`,
      );
    }
    const unnamed = unnamedDependencyFindings(report);
    if (unnamed > 0) {
      log.warn(
        `--${flag}: the scan is marked failed, because ${unnamed} dependency finding(s) have no package: GitLab would take them as fixed`,
      );
    }
    await attempt(flag, async () => {
      const ds = dependencyScanningReport(
        report,
        { start: new Date(report.analysisDate), end: now() },
        { redaction: gitlab.redaction, incomplete: gitlab.incomplete },
      );
      const w = await writeGitLabReport(
        flag,
        io.cwd,
        dependencyFile,
        ds.vulnerabilities,
        (vulnerabilities) => ({ ...ds, vulnerabilities }),
      );
      written(flag, 'Dependency Scanning vulnerabilities', w);
    });
  }
}

function summary(report: Report): string {
  return (
    `${report.files.length} files, ${report.findings.length} findings, ` +
    `${report.duplications.length} duplications, new code ${report.scm.baseline.status}`
  );
}

/**
 * `qualor scan` (config.md §5, §7). With `--dry-run` the report is written to `--output`.
 * Otherwise it is uploaded (ruling E5), and with `gate.wait` the gate verdict becomes the exit
 * code (ruling E6); a required analyzer failure uploads and then exits 3 at once (ruling E3).
 */
export async function runScan(
  flags: ScanFlags,
  io: CliIO,
  log: Logger,
  deps: ScanDeps = {},
): Promise<ExitCode> {
  const settings = loadSettings({ cwd: io.cwd, env: io.env, flags, log });
  const analyzers = deps.analyzers ?? builtinAnalyzers();
  // A configuration error of an enabled analyzer stops the scan before any git, tool or network
  // call (ruling V4: a PMD ruleset that references a URL).
  for (const analyzer of analyzers) {
    if (settings.config.analyzers[analyzer.id].enabled === false) continue;
    const problem = analyzer.checkConfig?.(settings.root, settings.config, io.env) ?? null;
    if (problem !== null) throw new CliError(EXIT.USAGE, `analyzers.${analyzer.id}: ${problem}`);
  }
  if (flags.dryRun && flags.output === undefined) {
    throw new CliError(EXIT.USAGE, '--dry-run needs --output FILE');
  }
  // scm.md §9: a report file that cannot be written is a usage error before any work.
  if (flags.gitlabCodeQuality !== undefined) {
    checkReportPath('gitlab-code-quality', io.cwd, flags.gitlabCodeQuality);
  }
  if (flags.gitlabSast !== undefined) checkReportPath('gitlab-sast', io.cwd, flags.gitlabSast);
  if (flags.gitlabDependencyScanning !== undefined) {
    checkReportPath('gitlab-dependency-scanning', io.cwd, flags.gitlabDependencyScanning);
  }
  if (!flags.dryRun) requireServer(settings);
  // Ruling V8 and the server settings (URL shape, token, CA file) exit 2 before any request;
  // under --dry-run a repo-chosen URL only warns and nothing is sent.
  const found = serverEndpoint(settings, { upload: !flags.dryRun, log, env: io.env });
  // The upload's proxy settings (ruling V9) come from the environment the CLI was given.
  const endpoint = found === null ? null : { ...found, env: io.env };
  const projectKey = settings.config.project.key;
  if (projectKey === undefined || projectKey === '') {
    throw new CliError(
      EXIT.USAGE,
      'no project key: set project.key, QUALOR_PROJECT_KEY or --project-key (in CI it defaults to the project path)',
    );
  }
  const { report, failed, gitlab } = await buildReport(
    settings,
    flags,
    projectKey,
    endpoint,
    analyzers,
    io,
    log,
    deps,
  );
  const failedRequired = (): ExitCode => {
    log.error(`required analyzers failed: ${failed.join(', ')}`);
    return EXIT.ANALYZER_FAILED;
  };
  await writeGitLabReports(flags, report, gitlab, io, log, deps.now ?? (() => new Date()));

  if (flags.dryRun) {
    const outPath = path.resolve(io.cwd, flags.output ?? '');
    const bytes = await writeReport(report, outPath);
    log.info(`wrote ${outPath} (${bytes} bytes): ${summary(report)}`);
    return failed.length > 0 ? failedRequired() : EXIT.OK;
  }

  if (endpoint === null) throw new Error('internal error: requireServer passed without a server');
  const { analysisId } = await withPrivateReportFile(report, ({ file, size }) => {
    log.info(`uploading the report (${size} bytes gzipped): ${summary(report)}`);
    return uploadReport(
      endpoint,
      { projectKey, file, size },
      { log, ...(deps.wait !== undefined && { wait: deps.wait }) },
    );
  });
  log.info(`analysis ${analysisId} queued on ${new URL(endpoint.url).origin}`);
  // Ruling E3: the report is uploaded (the failed engine is recorded and its issues stay open,
  // server ruling T2), but the gate is not awaited: exit 3 wins.
  if (failed.length > 0) return failedRequired();
  const { gate } = settings.config;
  if (!gate.wait) {
    log.info('not waiting for the quality gate (gate.wait is false)');
    return EXIT.OK;
  }
  const analysis = await waitForAnalysis(endpoint, analysisId, {
    timeoutMs: gate.timeoutSeconds * 1000,
    log,
    ...(deps.wait !== undefined && { wait: deps.wait }),
    ...(deps.clock !== undefined && { now: deps.clock }),
  });
  const code = gateExitCode(analysis, gate.failOnError);
  for (const line of describeGate(analysis)) {
    if (code === EXIT.OK) log.info(line);
    else log.error(line);
  }
  return code;
}
