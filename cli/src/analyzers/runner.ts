import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { engineMapping, type Language, type QualorConfig } from '@qualor/shared';
import type { ScopeFile } from '../discovery/discover';
import type { Logger } from '../log';
import { findRepoBinary, resolveBinary } from './binary';
import { confineAnalyzerEnv, mergeAnalyzerEnv, sanitizeAnalyzerEnv } from './env';
import { killActiveProcesses, runProcess } from './process';
import type {
  Analyzer,
  AnalyzerContext,
  DotnetRun,
  ExecOptions,
  Preparation,
  SarifCapture,
} from './types';

/** Same bound as external SARIF (ruling C10): larger JSON risks V8's string limit. */
const MAX_SARIF_BYTES = 256 * 1024 * 1024;

/** config.md §6: at most min(4, cpus) analyzers at once. */
function defaultConcurrency(): number {
  return Math.max(1, Math.min(4, os.availableParallelism()));
}

export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    for (let i = next++; i < items.length; i = next++) {
      results[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
}

export interface RunAnalyzersOptions {
  root: string;
  config: QualorConfig;
  files: readonly ScopeFile[];
  log: Logger;
  env?: Readonly<Record<string, string | undefined>>;
  concurrency?: number;
  tempRoot?: string;
  /** `qualor dotnet end`'s logs (config.md §6.1); absent or null in a plain `qualor scan`. */
  dotnet?: DotnetRun | null;
}

function readSarif(file: string, log: Logger): { value: unknown } | string {
  let size: number;
  try {
    size = statSync(file).size;
  } catch {
    return 'produced no SARIF output';
  }
  if (size > MAX_SARIF_BYTES)
    return `SARIF output is larger than ${MAX_SARIF_BYTES / 1024 / 1024} MiB`;
  try {
    return { value: JSON.parse(readFileSync(file, 'utf8')) as unknown };
  } catch (err) {
    // Fix-round-2 finding 1: V8's SyntaxError quotes a slice of the malformed input in its
    // message (e.g. `Unexpected token 'g', "{"runs": ghp_SUPERS"... is not valid JSON`), which
    // could be a secret an analyzer wrote out; `reason` stays a fixed string, detail goes to the
    // debug log only.
    log.debug(
      `SARIF output at ${file} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
    return 'SARIF output is not valid JSON';
  }
}

/**
 * The environment of an analyzer's process, a run's or a `ctx.exec` command's: `base` with the
 * command's own `env` on top, without the names `dropEnv` names (ruling A9-18), then sanitized and
 * confined (both idempotent, so an already sanitized `base` stays as it was). Exported for direct
 * testing.
 */
export function execEnv(
  base: Readonly<Record<string, string | undefined>>,
  options: Pick<ExecOptions, 'env' | 'dropEnv'>,
  root: string,
): Record<string, string> {
  const merged = mergeAnalyzerEnv(base, options.env);
  const dropEnv = options.dropEnv;
  const kept =
    dropEnv === undefined
      ? merged
      : Object.fromEntries(Object.entries(merged).filter(([name]) => !dropEnv(name)));
  return confineAnalyzerEnv(sanitizeAnalyzerEnv(kept), root);
}

/** Fix-round-2 finding 5: only a missing binary is "not installed"; anything else (e.g.
 * permission denied) is a distinct, still-fixed message. Exported for direct testing. */
export function spawnFailureReason(code: string | undefined): string {
  return code === 'ENOENT' ? 'not installed' : 'could not start';
}

/**
 * Fix-round-2 finding 2: every analyzer work directory currently on disk (it may hold a SARIF
 * file with secret plaintext, e.g. Gitleaks). The SIGINT/SIGTERM/SIGHUP handler below removes these
 * itself, because `process.exit()` does not unwind `capture()`'s pending `finally` and would
 * otherwise leave them behind in `os.tmpdir()`.
 */
const activeWorkDirs = new Set<string>();

/** Windows can briefly hold a lock on a just-closed file/directory (EBUSY/EPERM); a few retries
 * clear most of those without the caller having to do anything (fix-round-3 finding 2). */
const RM_OPTIONS = { recursive: true, force: true, maxRetries: 3, retryDelay: 100 } as const;

/** Never throws, even if `log.debug` itself does — logging must never break a cleanup path. */
function safeDebug(log: Logger | undefined, message: string): void {
  try {
    log?.debug(message);
  } catch {
    // ignored: a broken logger must not stop cleanup or the exit path that follows it
  }
}

function removeWorkDir(
  dir: string,
  log?: Logger,
  remove: (dir: string) => void = (d) => rmSync(d, RM_OPTIONS),
): void {
  try {
    remove(dir);
  } catch (err) {
    safeDebug(
      log,
      `could not remove analyzer work directory ${dir}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Removes every currently active analyzer work directory. A failure on one directory (logged at
 * debug, never thrown) does not stop the rest from being removed. `remove` is overridable only
 * for testing; production callers always get the real, retrying `rmSync`.
 */
export function removeActiveWorkDirs(log?: Logger, remove?: (dir: string) => void): void {
  for (const dir of activeWorkDirs) removeWorkDir(dir, log, remove);
  activeWorkDirs.clear();
}

/**
 * Fix-round-2 finding 3 / fix-round-3 finding 2: kills every tracked analyzer process tree and
 * removes every tracked work directory, then returns the conventional 128+signal exit code —
 * never throwing, so the SIGINT/SIGTERM/SIGHUP handler below always reaches `process.exit()` even if a
 * cleanup step misbehaves. Exported for direct testing of that guarantee.
 */
type CleanupSignal = 'SIGINT' | 'SIGTERM' | 'SIGHUP';

const SIGNAL_EXIT: Record<CleanupSignal, number> = { SIGHUP: 129, SIGINT: 130, SIGTERM: 143 };

/** SIGHUP (the terminal or the CI runner went away) exists on POSIX only. */
const CLEANUP_SIGNALS: readonly CleanupSignal[] =
  process.platform === 'win32' ? ['SIGINT', 'SIGTERM'] : ['SIGINT', 'SIGTERM', 'SIGHUP'];

export function emergencyCleanup(signal: CleanupSignal, log: Logger): number {
  safeDebug(
    log,
    `${signal}: killing active analyzer processes and removing their work directories`,
  );
  try {
    killActiveProcesses();
    removeActiveWorkDirs(log);
  } catch (err) {
    safeDebug(
      log,
      `${signal}: cleanup failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return SIGNAL_EXIT[signal];
}

/**
 * Installed only for the duration of one `runAnalyzers` call (the caller removes the listeners
 * again once it returns), so default signal behaviour applies the rest of the time.
 */
function installEmergencyCleanup(log: Logger): () => void {
  const installed = CLEANUP_SIGNALS.map((signal) => {
    const handler = () => process.exit(emergencyCleanup(signal, log));
    process.on(signal, handler);
    return { signal, handler };
  });
  return () => {
    for (const { signal, handler } of installed) process.removeListener(signal, handler);
  };
}

async function capture(
  analyzer: Analyzer,
  o: RunAnalyzersOptions,
  languages: ReadonlySet<Language>,
): Promise<SarifCapture> {
  const settings = o.config.analyzers[analyzer.id];
  const timeoutSeconds = 'timeoutSeconds' in settings ? settings.timeoutSeconds : 0;
  const required = settings.enabled === true;
  const mapping = engineMapping(analyzer.id);
  const base = {
    engineId: analyzer.id,
    kind: 'builtin' as const,
    version: null,
    required,
    ...(mapping !== undefined && { mapping }),
    ...(analyzer.ruleLanguages !== undefined && { ruleLanguages: analyzer.ruleLanguages }),
  };
  const skipped = (reason: string, isRequired = required, unavailable = false): SarifCapture => {
    o.log.info(`${analyzer.id}: skipped (${reason})`);
    return {
      ...base,
      required: isRequired,
      status: 'skipped',
      reason,
      durationMs: 0,
      ...(unavailable && { unavailable }),
    };
  };
  if (settings.enabled === false) return skipped('disabled in qualor.yml', false);
  if (
    settings.enabled === 'auto' &&
    analyzer.languages.length > 0 &&
    !analyzer.languages.some((l) => languages.has(l))
  ) {
    return skipped(`no ${analyzer.languages.join('/')} files in scope`);
  }

  const workDir = mkdtempSync(path.join(o.tempRoot ?? os.tmpdir(), `qualor-${analyzer.id}-`));
  activeWorkDirs.add(workDir);
  const started = performance.now();
  const parentEnv = o.env ?? process.env;
  // Secrets stripped, and PATH/CLASSPATH never pointing into the checkout (ruling V3).
  const analyzerEnv = confineAnalyzerEnv(sanitizeAnalyzerEnv(parentEnv), o.root);
  try {
    const ctx: AnalyzerContext = {
      root: o.root,
      config: o.config,
      languages,
      files: o.files,
      workDir,
      log: o.log,
      dotnet: o.dotnet ?? null,
      // Ruling V3: every built-in analyzer binary comes from PATH or the scanner image, never
      // from the repository being scanned.
      resolveBinary: (name) => resolveBinary(name, { root: o.root, env: parentEnv }),
      repoBinary: (name) => findRepoBinary(name, { root: o.root, env: parentEnv }),
      env: analyzerEnv,
      exec: (command, args, options) =>
        runProcess(
          {
            command,
            args,
            cwd: options.cwd ?? o.root,
            env: execEnv(analyzerEnv, options, o.root),
            timeoutMs: options.timeoutMs,
          },
          o.log,
        ),
    };
    let prep: Preparation;
    try {
      prep = await analyzer.prepare(ctx);
    } catch (err) {
      // Fix-round finding 9: a throwing adapter must not crash the whole analyzer batch (which
      // `mapLimit`'s `Promise.all` would otherwise propagate as a full-scan failure) — record it
      // as a failed engine and let the other analyzers continue.
      const message = err instanceof Error ? (err.stack ?? err.message) : String(err);
      o.log.debug(`${analyzer.id}: prepare() threw: ${message}`);
      o.log.error(`${analyzer.id}: failed to prepare`);
      return {
        ...base,
        status: 'failed',
        reason: 'failed to prepare',
        durationMs: performance.now() - started,
      };
    }
    if ('skip' in prep || 'unavailable' in prep) {
      const unavailable = 'unavailable' in prep;
      const reason = 'unavailable' in prep ? prep.unavailable : prep.skip;
      if (!required) return skipped(reason, required, unavailable);
      o.log.error(`${analyzer.id}: ${reason}`);
      return {
        ...base,
        status: 'failed',
        reason,
        durationMs: performance.now() - started,
        ...(unavailable && { unavailable }),
      };
    }
    if ('collected' in prep) {
      return {
        ...base,
        status: 'ok',
        reason: null,
        durationMs: performance.now() - started,
        version: prep.collected.version,
        sarif: prep.collected.sarif,
      };
    }
    const run = prep.run;
    // Fix-round finding 3: analyzers run repo-controlled code (ESLint plugins, PMD rulesets,
    // Semgrep rules), so the server token (and anything else that looks like a Qualor secret)
    // must never reach their process environment.
    // An adapter's own `env` is merged in and then sanitized again, so it cannot re-add one.
    const childEnv = execEnv(
      parentEnv,
      {
        ...(run.env !== undefined && { env: run.env }),
        ...(run.dropEnv !== undefined && { dropEnv: run.dropEnv }),
      },
      o.root,
    );
    const result = await runProcess(
      {
        command: run.command,
        args: run.args,
        cwd: run.cwd,
        env: childEnv,
        timeoutMs: timeoutSeconds * 1000,
      },
      o.log,
    );
    const done = (status: SarifCapture['status'], reason: string | null): SarifCapture => {
      if (reason !== null) o.log.warn(`${analyzer.id}: ${status} (${reason})`);
      const roots = analyzer.sourceRoots?.(ctx);
      return {
        ...base,
        status,
        reason,
        durationMs: performance.now() - started,
        version: run.version ?? null,
        ...(roots !== undefined && { sourceRoots: roots }),
        ...(run.database !== undefined && { database: run.database }),
        ...(run.warnings !== undefined && { warnings: run.warnings }),
      };
    };
    // Fix-round finding 4: `reason` is a fixed message per failure kind, never the analyzer's own
    // stdout/stderr (config.md §6): that stays in the debug log only (`runProcess` already logs
    // it there).
    if (result.timedOut) return done('timeout', `timed out after ${timeoutSeconds} s`);
    if (result.spawnError !== undefined)
      return done('failed', spawnFailureReason(result.spawnErrorCode));
    if (result.exitCode === null || !run.okExitCodes.includes(result.exitCode)) {
      const detail = run.failureDetail?.(result.exitCode, result.stderr) ?? null;
      if (detail !== null) o.log.warn(`${analyzer.id}: ${detail}`);
      return done('failed', `exited with code ${result.exitCode ?? 'null'}`);
    }
    for (const line of run.configWarnings?.(result.stderr) ?? []) {
      o.log.warn(`${analyzer.id}: ${line}`);
    }
    const sarif = readSarif(run.sarifPath, o.log);
    if (typeof sarif === 'string') return done('failed', sarif);
    if (run.transform === undefined) return { ...done('ok', null), sarif: sarif.value };
    let converted: unknown;
    try {
      converted = run.transform(sarif.value, result.stdout);
    } catch (err) {
      // Same rule as for invalid JSON: the detail (which may quote tool output) is debug-only.
      o.log.debug(
        `${analyzer.id}: output conversion failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return done('failed', 'output could not be converted to SARIF');
    }
    return { ...done('ok', null), sarif: converted };
  } finally {
    activeWorkDirs.delete(workDir);
    removeWorkDir(workDir, o.log);
  }
}

export async function runAnalyzers(
  analyzers: readonly Analyzer[],
  o: RunAnalyzersOptions,
): Promise<SarifCapture[]> {
  // Fix-round findings 10 and (round 2) 2/3: kill every analyzer process tree and remove every
  // work directory on Ctrl+C / job cancellation, only for the duration of this call.
  const uninstall = installEmergencyCleanup(o.log);
  try {
    const languages = new Set(o.files.map((f) => f.language).filter((l) => l !== 'other'));
    return await mapLimit(analyzers, o.concurrency ?? defaultConcurrency(), (a) =>
      capture(a, o, languages),
    );
  } finally {
    uninstall();
  }
}

/**
 * config.md §7 exit code 3: required analyzers that failed or timed out. With `engines` (the
 * report's engine entries), a required engine whose run succeeded but whose SARIF could not be
 * normalised counts too: the report records it as failed, so the exit code must agree.
 */
export function requiredFailures(
  captures: readonly SarifCapture[],
  engines: readonly { id: string; status: string }[] = [],
): string[] {
  const failed = (status: string) => status === 'failed' || status === 'timeout';
  const reported = new Map(engines.map((e) => [e.id, e.status]));
  return captures
    .filter((c) => c.required && (failed(c.status) || failed(reported.get(c.engineId) ?? '')))
    .map((c) => c.engineId);
}
