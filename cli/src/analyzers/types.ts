import type {
  EngineMapping,
  Language,
  NormalizeWarning,
  QualorConfig,
  ReportEngine,
} from '@qualor/shared';
import type { ScopeFile } from '../discovery/discover';
import type { Logger } from '../log';
import type { ProcessResult } from './process';
import type { MergedLogs } from './roslyn-logs';

export type AnalyzerId = keyof QualorConfig['analyzers'];

/** What `qualor dotnet end` found for the `roslyn` engine (config.md §6.1, ruling D7). */
export type DotnetRun =
  | { kind: 'collected'; merged: MergedLogs }
  | { kind: 'no-session' }
  | { kind: 'no-build' }
  | { kind: 'not-compiled' }
  | { kind: 'hook-failed'; reason: string };

export interface AnalyzerContext {
  root: string;
  config: QualorConfig;
  /** Languages detected in scope (never 'other'). */
  languages: ReadonlySet<Language>;
  files: readonly ScopeFile[];
  /** Private temporary directory, removed after the run. */
  workDir: string;
  log: Logger;
  /** `qualor dotnet end`'s logs for the roslyn engine; null in a plain `qualor scan`. */
  dotnet: DotnetRun | null;
  /**
   * config.md §6 (ruling V3): PATH, then the scanner image, never a file inside the repository;
   * null when the tool is not installed there.
   */
  resolveBinary(name: string): string | null;
  /**
   * A copy of the binary the repository itself provides, which `resolveBinary` refused. Never
   * run it: it only lets a skip reason say why that copy was not used.
   */
  repoBinary(name: string): string | null;
  /** The analyzer environment (secrets stripped, config.md §6) that `exec` and the run use. */
  env: Readonly<Record<string, string | undefined>>;
  /**
   * The only way an adapter may run a helper command during `prepare()` (e.g. `eslint
   * --version`): no shell, the analyzer environment (secrets stripped, config.md §6), the whole
   * process tree killed at `timeoutMs`, and tracked so Ctrl+C kills it too. `cwd` defaults to
   * `root`. Output tails are for parsing and the debug log only, never for the report.
   */
  exec(command: string, args: readonly string[], options: ExecOptions): Promise<ProcessResult>;
}

export interface ExecOptions {
  timeoutMs: number;
  cwd?: string;
}

export interface AnalyzerCommand {
  command: string;
  args: readonly string[];
  cwd: string;
  /** Added to the analyzer environment; the result is sanitized again (config.md §6). */
  env?: Readonly<Record<string, string>>;
  /**
   * Variables removed from the tool's environment after `env` is added (Trivy: every `TRIVY_*`,
   * which would configure it behind the command line's back, config.md §6).
   */
  dropEnv?(name: string): boolean;
  /** Where the tool writes SARIF 2.1.0 (config.md §6). */
  sarifPath: string;
  /** Exit codes that mean "ran fine" (many linters exit 1 when they found issues). */
  okExitCodes: readonly number[];
  version?: string | null;
  /** The vulnerability database the tool uses (report-format.md §5, `engines[].database`). */
  database?: NonNullable<ReportEngine['database']>;
  /** Report warnings the adapter already knows of (`VULNERABILITY_DB_STALE`). */
  warnings?: readonly NormalizeWarning[];
  /**
   * Turns the tool's own JSON output (read from `sarifPath` with the same size bound) into a SARIF
   * 2.1.0 log, for tools without a usable SARIF writer (ESLint: `json-with-metadata`). A throw
   * records the engine as failed with a fixed reason. `stdout` is the run's captured stdout tail
   * (same bound as `ProcessResult.stdout`), for a tool that reports extra detail there the SARIF
   * itself does not carry (sonarjs's one-line JSON summary); most adapters ignore it and return
   * `output` unchanged or converted, as before this parameter existed.
   */
  transform?(output: unknown, stdout: string): unknown;
  /**
   * A run whose exit code is not in `okExitCodes`: one line from the tool's stderr tail that says
   * why, or null. It is logged at warn so the user sees the reason (a configuration stylelint
   * refuses); the report `reason` stays the fixed "exited with code N" (config.md §6).
   */
  failureDetail?(exitCode: number | null, stderr: string): string | null;
}

export type Preparation =
  | { run: AnalyzerCommand }
  /**
   * The scan did what the configuration asked and there is nothing to run (no ESLint
   * configuration, no PMD rulesets, no compiled classes, no Semgrep rules...): skipped under
   * auto, failed under true. Complete for ruling G6.
   */
  | { skip: string }
  /**
   * The tool cannot run here at all (not installed, or a runtime it needs, such as java, is
   * missing): skipped under auto, failed under true, and marked `unavailable` on the capture, so
   * ruling G6 counts the engine as incomplete.
   */
  | { unavailable: string }
  /**
   * SARIF the tool already wrote outside the CLI (Roslyn, inside the project's build between
   * `qualor dotnet begin` and `end`): recorded as `ok` without running anything.
   */
  | { collected: { sarif: unknown; version: string | null } };

/** What the step 8–12 adapters implement. */
export interface Analyzer {
  id: AnalyzerId;
  /** Runs under `enabled: auto` only if one of these was detected; [] = always. */
  languages: readonly Language[];
  prepare(ctx: AnalyzerContext): Promise<Preparation>;
  /**
   * A configuration error in this analyzer's settings (exit 2, config.md §7), checked by
   * `qualor scan` before anything runs, or null. Only for problems no environment can fix (for
   * example a PMD ruleset that references a URL, ruling V4); a missing tool is a skip. `env` is
   * the CLI's own environment (Gitleaks lets `GITLEAKS_CONFIG` choose the config).
   */
  checkConfig?(
    root: string,
    config: QualorConfig,
    env?: Readonly<Record<string, string | undefined>>,
  ): string | null;
  /** Prefixes the normaliser tries for tool paths (e.g. SpotBugs class-relative paths). */
  sourceRoots?(ctx: AnalyzerContext): readonly string[];
  /** Copied into every rule's `languages` (report-format §5), e.g. `['java']` for PMD. */
  ruleLanguages?: readonly Language[];
}

export type EngineStatus = 'ok' | 'failed' | 'skipped' | 'timeout';

/** One engine's raw outcome, before normalisation (built-in analyzers and external SARIF). */
export interface SarifCapture {
  engineId: string;
  kind: 'builtin' | 'external';
  status: EngineStatus;
  reason: string | null;
  durationMs: number;
  version: string | null;
  /** `enabled: true`: a failure or timeout makes the scan exit 3. */
  required: boolean;
  /** Parsed SARIF JSON when `status` is `ok`. */
  sarif?: unknown;
  mapping?: EngineMapping;
  sourceRoots?: readonly string[];
  /** The command's `database`, for the engine entry, when the tool ran. */
  database?: NonNullable<ReportEngine['database']>;
  /** The command's `warnings`, for the report, when the tool ran. */
  warnings?: readonly NormalizeWarning[];
  ruleLanguages?: readonly Language[];
  /**
   * The tool could not run here (a `Preparation` of `unavailable`): ruling G6 counts the engine
   * as incomplete, like a failure or a timeout. Never set for a disabled analyzer.
   */
  unavailable?: boolean;
}
