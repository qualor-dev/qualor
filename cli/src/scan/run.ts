import path from 'node:path';
import { engineMapping, type QualorConfig, type Report } from '@qualor/shared';
import { loadExternalSarif } from '../analyzers/external';
import { fileLines, normalizeCaptures } from '../analyzers/normalize';
import { builtinAnalyzers } from '../analyzers/registry';
import {
  createWorkDir,
  releaseWorkDir,
  requiredFailures,
  runAnalyzers,
  withEmergencyCleanup,
} from '../analyzers/runner';
import { LICENSE_ENGINE_ID } from '../analyzers/trivy-licenses';
import type { Analyzer, DotnetRun } from '../analyzers/types';
import type { ScanFlags } from '../args';
import { platformId } from '../commands/version';
import type { CiMergeRequest } from '../config/ci';
import { loadSettings, requireServer, type Settings } from '../config/settings';
import { importCoverage } from '../coverage/import';
import { discoverFiles } from '../discovery/discover';
import { detectDuplications } from '../duplication/detect';
import { CliError, EXIT, type ExitCode } from '../errors';
import { createGit, type Git } from '../git/git';
import { fetchPolicy, resolveScm } from '../git/scm';
import { VERSION } from '../index';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { loadParsers, type Parsers } from '../parse/grammars';
import { baseSecretScan, SECRET_ENGINE } from '../review/base-secrets';
import { fetchReviewContext, type ReviewContext } from '../review/context';
import { SnapshotDeadline, SnapshotTooSlow } from '../review/deadline';
import { maskSecrets, prepareSecrets } from '../review/redact';
import { buildReviewSnapshot, type BuiltSnapshot } from '../review/snapshot';
import { uploadReviewSnapshot } from '../review/upload';
import { httpBaselineClient, type NewCodeBaselineClient } from '../server/baseline-client';
import { serverEndpoint } from '../server/endpoint';
import { describeGate, gateExitCode, waitForAnalysis } from '../server/gate';
import { clean, type ServerEndpoint } from '../server/http';
import { uploadReport } from '../server/upload';
import { checkServerVersion } from '../server/version';
import { Warnings } from '../warnings';
import { collectDependencies, type DependencyPassHooks } from './dependencies';
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
  /** The clock of the gate deadline and of the AI review snapshot's (tests move it). */
  clock?: () => number;
  /** `qualor dotnet end`'s logs (config.md §6.1); absent or null in a plain `qualor scan`. */
  dotnet?: DotnetRun | null;
  /** undefined: ask the server for its version when a scan starts; null: do not (tests). */
  serverVersion?: ((endpoint: ServerEndpoint, log: Logger) => Promise<unknown>) | null;
  /** `qualor dotnet end`'s own warnings (config.md §6.1), added to the report's `warnings`. */
  extraWarnings?: readonly { code: string; message: string }[];
  /** The Trivy licence pass's process helper and binary lookup (tests fake them). */
  licensePass?: DependencyPassHooks;
  /**
   * Where the AI review's snapshot and the scan of its merge base make their private directories
   * (tests); the system's temporary directory by default.
   */
  reviewTempRoot?: string;
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

async function buildReport(inputs: {
  settings: Settings;
  flags: ScanFlags;
  projectKey: string;
  endpoint: ServerEndpoint | null;
  analyzers: readonly Analyzer[];
  io: CliIO;
  log: Logger;
  deps: ScanDeps;
}): Promise<BuiltReport> {
  const { settings, flags, projectKey, endpoint, analyzers, io, log, deps } = inputs;
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
  // The scan's scope: a finding (and a lockfile of the licence pass) elsewhere is left out.
  const knownPaths = new Set(files.map((f) => f.path));
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
    knownPaths,
    log,
    onSecrets: (texts, unknown) => {
      redaction = { texts, unknown };
    },
  });
  warnings.addAll(engines.warnings);
  // Spec §1: the licence pass, after the analyzers, wherever Trivy runs. Its failure or timeout
  // is a warning and no inventory; the vulnerability findings above are unaffected.
  const licenses = analyzers.some((a) => a.id === 'trivy')
    ? await collectDependencies({
        root,
        config,
        knownPaths,
        log,
        env: io.env,
        ...deps.licensePass,
      })
    : null;
  if (licenses !== null) warnings.addAll(licenses.warnings);

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
          engines:
            licenses === null
              ? engines
              : { ...engines, engines: [...engines.engines, licenses.engine] },
          warnings,
          ...(licenses?.entries !== undefined && { dependencies: licenses.entries }),
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
      // The licence pass puts nothing in GitLab's files, so it never marks them incomplete.
      incomplete: report.engines
        .filter((e) => e.id !== LICENSE_ENGINE_ID)
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

interface ReviewSnapshotOptions {
  endpoint: ServerEndpoint;
  settings: Settings;
  projectKey: string;
  /** The analysis of the report just uploaded. */
  analysisId: string;
  /** The report uploaded: its merge request (CI's, or the one `--mr` names) and engine records. */
  report: Report;
  /** The secrets the scan's analyzers found, or that they are unknown. */
  redaction: GitLabRedaction;
  /** The scan's analyzers: its secret engine scans the merge base's files too (ruling R13). */
  analyzers: readonly Analyzer[];
  /** The engines that did not complete, ruling G6's list (`BuiltReport.gitlab.incomplete`). */
  incomplete: readonly string[];
  /** The CLI's environment, as the scan's analyzers had it (`GITLEAKS_CONFIG`). */
  env: CliIO['env'];
  log: Logger;
  deps: ScanDeps;
}

const SNAPSHOT_TOO_SLOW =
  'AI review: building the repository snapshot took longer than 10 minutes, so none is sent';

/** An engine whose findings are secrets the report masks (its mapping's `redactRegion`). */
function redactsSecrets(engineId: string): boolean {
  const redact = engineMapping(engineId)?.redactRegion;
  return redact !== undefined && redact !== false;
}

/**
 * Whether `analyzers.semgrep.configs` names nothing but the image's own `qualor-default`: no rule
 * file of the user's. Read from the scan's configuration, not from the engine's reason text.
 */
const semgrepOnDefaults = (config: QualorConfig): boolean =>
  config.analyzers.semgrep.configs.every((entry) => entry === 'qualor-default');

/**
 * Review Focus 2: the scan's secret scans that did not complete, read from the report's engine
 * records (`engines`), the analyzers the scan ran and `incomplete`, ruling G6's list (`buildReport`:
 * failed, timed out, or unavailable, the tool could not run here). Every engine whose findings are
 * secrets the report masks (Gitleaks, and the secret rules of Semgrep and of Qualor's rules) that
 * qualor.yml does not switch off must have looked at the files. In order:
 * - no record at all: unknown, so not complete;
 * - `ok`: complete;
 * - failed or timed out: not complete, whatever the list says;
 * - skipped: it scanned nothing, which is complete only when there was nothing to scan.
 *   - Gitleaks: never. It has something to scan in every repository, and its only skip is a
 *     `configFile` that does not exist or is not a regular file.
 *   - an engine in the list: its tool could not run here.
 *   - Semgrep whose configs name anything but `qualor-default`: the rule files the configuration
 *     names never ran (a path that does not exist). Semgrep on its defaults ran nothing because
 *     the scanner image ships no rule file: nothing to run.
 * - ok, but with a `SEMGREP_CONFIG_MISSING` report warning (`warnings`): it ran the rule files that
 *   exist, and a file the configuration names did not, so its secret rules may be missing.
 *   - Qualor's rules without their pack or without a file of their languages: nothing to run.
 */
export function incompleteSecretScans(
  analyzers: readonly Pick<Analyzer, 'id'>[],
  engines: readonly Pick<Report['engines'][number], 'id' | 'status'>[],
  config: QualorConfig,
  incomplete: readonly string[],
  warnings: readonly { code: string }[] = [],
): string[] {
  const missingConfig = warnings.some((w) => w.code === 'SEMGREP_CONFIG_MISSING');
  const status = new Map(engines.map((e) => [e.id, e.status]));
  const unavailable = new Set(incomplete);
  const unfinished = (id: string): boolean => {
    const recorded = status.get(id);
    if (recorded === undefined) return true;
    if (recorded === 'ok') return id === 'semgrep' && missingConfig;
    if (recorded !== 'skipped') return true;
    if (id === SECRET_ENGINE || unavailable.has(id)) return true;
    return id === 'semgrep' && !semgrepOnDefaults(config);
  };
  return analyzers
    .filter((a) => redactsSecrets(a.id) && config.analyzers[a.id].enabled !== false)
    .filter((a) => unfinished(a.id))
    .map((a) => a.id);
}

/** What CI lacks when it does not name the merge request's head commit, for the warning. */
function unnamedHead(ci: Settings['ci']): string {
  if (ci.provider === 'github') return "the event's pull_request.head.sha is not a commit id";
  const merged = ci.gitlab?.mergeRequestEventType;
  return merged === 'merged_result' || merged === 'merge_train'
    ? `CI_MERGE_REQUEST_SOURCE_BRANCH_SHA is not a commit id in this ${merged.replace('_', ' ')} pipeline`
    : 'CI_COMMIT_SHA is not a commit id';
}

/** Why the snapshot could not be built, for its warning. */
function unavailableText(
  reason: Extract<BuiltSnapshot, { kind: 'unavailable' }>['reason'],
  o: { headSha: string; targetBranch: string; autoFetch: boolean },
): string {
  switch (reason) {
    case 'head_missing':
      return o.autoFetch
        ? `the merge request's head commit ${o.headSha} is not in the clone and could not be fetched (a checkout with more history, a larger fetch-depth, has it)`
        : `the merge request's head commit ${o.headSha} is not in the clone (scm.autoFetch is false)`;
    case 'no_merge_base':
      return `the merge request's head and origin/${o.targetBranch} have no common commit in this clone`;
    case 'too_large':
      return "the merge request's changes alone are over the server's snapshot limits";
    case 'head_unscanned':
      return 'the head files that differ from the scanned checkout could not be scanned';
  }
}

/**
 * The snapshot of `s.mr`, built in `s.tempRoot` and uploaded, then removed whatever happens. Its
 * warnings are those of `sendReviewSnapshot`; it throws on a git, disk or network failure, and
 * SnapshotTooSlow when the snapshot is not built by `s.deadline`: git and the merge base's secret
 * scan stop there (the snapshot is not built at all, or not sent).
 */
async function buildAndUpload(
  o: ReviewSnapshotOptions,
  s: {
    mr: CiMergeRequest & { headSha: string };
    context: ReviewContext;
    secrets: readonly string[];
    tempRoot: string;
    deadline: SnapshotDeadline;
  },
): Promise<void> {
  const { settings, log } = o;
  const { mr, tempRoot, deadline } = s;
  // One directory for git and the secret engine, the scan root: the merge base's files are laid
  // out from git's working directory, and the head scan's paths, which the engine's path rules
  // and allowlists match, are the analyzers' root's.
  const root = settings.root;
  const policy = fetchPolicy(settings);
  let built: BuiltSnapshot;
  try {
    built = await buildReviewSnapshot({
      git: deadline.git(o.deps.git ?? createGit(root, o.env)),
      config: settings.config,
      headSha: mr.headSha,
      targetBranch: mr.targetBranch,
      sinceSha: s.context.lastReviewedCommit,
      mergeRequest: { id: mr.id, title: mr.title, description: mr.description },
      secrets: s.secrets,
      // The analyzers scanned the working tree: the head's files it does not hold as the head
      // does (a merge commit checked out, a file a CI step edited) are scanned again (ruling R14).
      secretsFrom: 'working-tree',
      baseSecrets: baseSecretScan({
        analyzers: o.analyzers,
        root,
        config: settings.config,
        env: o.env,
        log,
        tempRoot,
        deadline,
      }),
      limits: s.context.limits,
      policy,
      log,
      tempRoot,
    });
  } catch (err) {
    // A failure past the deadline came of it (a call it cut, or one it refused): it is the reason.
    if (deadline.passed) throw new SnapshotTooSlow();
    throw err;
  }
  // Whatever the build came to, it came too late: nothing is sent.
  if (deadline.passed) {
    if (built.kind === 'built') await built.cleanup();
    throw new SnapshotTooSlow();
  }
  if (built.kind === 'unavailable') {
    const why = unavailableText(built.reason, {
      headSha: mr.headSha,
      targetBranch: mr.targetBranch,
      autoFetch: policy.autoFetch,
    });
    log.warn(`AI review: no snapshot sent, ${why}`);
    return;
  }
  try {
    log.info(
      `AI review: uploading the repository snapshot (${built.files} files, ${built.size} bytes gzipped, ${built.redactions} secrets masked${built.partial ? "; partial: the server's limits left files out" : ''})`,
    );
    const outcome = await uploadReviewSnapshot(
      o.endpoint,
      { analysisId: o.analysisId, projectKey: o.projectKey, file: built.file, size: built.size },
      { log, ...(o.deps.wait !== undefined && { wait: o.deps.wait }) },
    );
    if (outcome === 'uploaded') log.info('AI review: repository snapshot uploaded');
  } finally {
    await built.cleanup();
  }
}

/**
 * AI review (6I-2): the merge request's repository snapshot, after its report, when the server
 * says AI review runs for the project. The snapshot is built with the scan's own configuration,
 * analyzers and secrets (the token among them), the merge base's files scanned by the same secret
 * engine from the same root (ruling R13), and is always removed afterwards (on Ctrl+C or a
 * cancelled job too). A scan that exits 3 sends none (`runScan` returns first). No snapshot goes
 * when a secret scan of the scan did not complete or its output could not be read (Review Focus
 * 2; one qualor.yml switches off is the user's choice, said once), or when the merge request's
 * head is unknown or not in the clone (ruling R12); each of those, a snapshot that cannot be
 * built, a refused upload (said by `uploadReviewSnapshot`) and any failure is one warning. A
 * snapshot not built within ten minutes of the path's start is not sent either (6I-3): git stops
 * at the deadline, and one warning says so. It never throws and never decides the exit code.
 * Nothing it logs holds a secret, the token or snapshot content.
 */
async function sendReviewSnapshot(o: ReviewSnapshotOptions): Promise<void> {
  const { settings, log } = o;
  const mr = settings.ci.mergeRequest;
  if (mr === null) return;
  const token = settings.token;
  const secrets = [...o.redaction.texts, ...(token === null || token === '' ? [] : [token])];
  const deadline = new SnapshotDeadline(o.deps.clock ?? Date.now);
  try {
    const context = await fetchReviewContext(
      o.endpoint,
      { projectKey: o.projectKey, mergeRequest: mr.id },
      log,
    );
    if (context === null) return;
    if (!context.review) {
      log.info(
        `AI review is off for this project (${context.reason ?? 'no reason given'}), so no repository snapshot is sent`,
      );
      return;
    }
    // The snapshot is of the merge request CI runs for (its head, title and description): never
    // sent with the analysis of another one.
    const reported = o.report.scm.mergeRequest;
    if (reported?.id !== mr.id || reported.targetBranch !== mr.targetBranch) {
      log.warn(
        'AI review: no snapshot sent, --mr and --mr-target name another merge request than the one CI runs for',
      );
      return;
    }
    // The secrets the scan found are unknown: none of them could be masked.
    if (o.redaction.unknown) {
      log.warn("AI review: no snapshot sent, the secret scan's output could not be read");
      return;
    }
    const incomplete = incompleteSecretScans(
      o.analyzers,
      o.report.engines,
      settings.config,
      o.incomplete,
      o.report.warnings,
    );
    if (incomplete.length > 0) {
      log.warn(
        `AI review: no snapshot sent, the secret scan (${incomplete.join(', ')}) did not complete`,
      );
      return;
    }
    if (mr.headSha === null) {
      log.warn(
        `AI review: no snapshot sent, the merge request's head commit is unknown (${unnamedHead(settings.ci)})`,
      );
      return;
    }
    // Switched off by the user: the shared patterns, and the secrets the other analyzers found,
    // mask the snapshot (and no line the merge request removes is sent, ruling R13).
    if (
      o.analyzers.some((a) => a.id === SECRET_ENGINE) &&
      settings.config.analyzers[SECRET_ENGINE].enabled === false
    ) {
      log.info(
        'AI review: the secret scan is off in qualor.yml; only built-in patterns mask secrets in the snapshot',
      );
    }
    const head = { ...mr, headSha: mr.headSha };
    // Everything the snapshot writes goes below one private directory, which Ctrl+C or a cancelled
    // job removes too: the snapshot holds the repository's code.
    await withEmergencyCleanup(log, async () => {
      const dir = createWorkDir('review', o.deps.reviewTempRoot);
      try {
        await buildAndUpload(o, { mr: head, context, secrets, tempRoot: dir, deadline });
      } finally {
        releaseWorkDir(dir, log);
      }
    });
  } catch (err) {
    if (err instanceof SnapshotTooSlow) {
      log.warn(SNAPSHOT_TOO_SLOW);
      return;
    }
    // A git, disk or network failure: its text masked like the snapshot, made safe for a terminal.
    const text = err instanceof Error ? err.message : String(err);
    log.warn(
      `AI review: no snapshot sent: ${clean(maskSecrets(text, prepareSecrets(secrets)).text)}`,
    );
  }
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
  log.info(`qualor ${VERSION} (${platformId()})`);
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
  if (endpoint !== null && deps.serverVersion !== null) {
    await (deps.serverVersion ?? checkServerVersion)(endpoint, log);
  }
  const { report, failed, gitlab } = await buildReport({
    settings,
    flags,
    projectKey,
    endpoint,
    analyzers,
    io,
    log,
    deps,
  });
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
  // server ruling T2), but the gate is not awaited: exit 3 wins. No AI review snapshot either: the
  // scan's results, the secrets it masks among them, may be incomplete.
  if (failed.length > 0) return failedRequired();
  if (settings.ci.mergeRequest !== null) {
    await sendReviewSnapshot({
      endpoint,
      settings,
      projectKey,
      analysisId,
      report,
      redaction: gitlab.redaction,
      analyzers,
      incomplete: gitlab.incomplete,
      env: io.env,
      log,
      deps,
    });
  }
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
