import { mkdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import {
  BUILTIN_EXCLUDES,
  REDACTED,
  REPORT_BOUNDS,
  type DependencyEntry,
  type NormalizeWarning,
  type QualorConfig,
  type ReportEngine,
} from '@qualor/shared';
import { resolveBinary as resolveOnPath } from '../analyzers/binary';
import { confineAnalyzerEnv, sanitizeAnalyzerEnv } from '../analyzers/env';
import {
  runProcess as realRunProcess,
  type ProcessResult,
  type ProcessSpec,
} from '../analyzers/process';
import { detailLine, stderrLines } from '../analyzers/reason';
import {
  createWorkDir,
  execEnv,
  releaseWorkDir,
  spawnFailureReason,
  withEmergencyCleanup,
} from '../analyzers/runner';
import {
  capInventory,
  LICENSE_ENGINE_ID,
  licenseCommand,
  licensesSkippedWarning,
  MAX_DEPENDENCIES,
  mergeDuplicates,
  trivyJsonToInventory,
} from '../analyzers/trivy-licenses';
import type { AnalyzerContext } from '../analyzers/types';
import { globMatcher } from '../discovery/discover';
import type { Logger } from '../log';

/** Same bound as the analyzers' SARIF output (runner.ts). */
const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

/** What the licence pass adds to the report (spec §1): its engine entry, the inventory, warnings. */
export interface DependencyPass {
  engine: ReportEngine;
  /** Absent when the pass did not complete: the report then has no `dependencies` field. */
  entries?: DependencyEntry[];
  warnings: NormalizeWarning[];
}

/** What a test replaces: the runner's process helper and the binary lookup. */
export interface DependencyPassHooks {
  runProcess?: (spec: ProcessSpec, log: Logger) => Promise<ProcessResult>;
  resolveBinary?: (name: string) => string | null;
}

export interface CollectDependenciesOptions extends DependencyPassHooks {
  root: string;
  config: QualorConfig;
  /**
   * The scan's files (the report's `files`): only their lockfiles enter the inventory, the
   * vulnerability pass's scope (`knownPaths` of `normalizeCaptures`).
   */
  knownPaths: ReadonlySet<string>;
  log: Logger;
  /** The CLI's own environment (the analyzers'). */
  env?: Readonly<Record<string, string | undefined>>;
  tempRoot?: string;
  /**
   * A tag scan (version mode) needs the inventory whatever `analyzers.trivy.licenses` says; only
   * `analyzers.trivy.enabled: false` still turns the pass off.
   */
  force?: boolean;
}

/** `analyzers.trivy`: the licence pass runs unless Trivy or the pass itself is switched off. */
export function licensePassEnabled(config: QualorConfig): boolean {
  const trivy = config.analyzers.trivy;
  return trivy.enabled !== false && trivy.licenses !== false;
}

/** Credentials in a URL (`https://user:password@host`) never reach the log. */
const scrubLine = (line: string) => line.replace(/\/\/[^/\s@]+@/g, `//${REDACTED}@`);

const warning = (code: string, message: string): NormalizeWarning => ({ code, message, count: 1 });

function readOutput(file: string): unknown {
  if (statSync(file).size > MAX_OUTPUT_BYTES) throw new Error('output larger than 256 MiB');
  return JSON.parse(readFileSync(file, 'utf8')) as unknown;
}

/** Trivy's licence report as read: the inventory before merging, and Trivy's version. */
interface TrivyInventory {
  parsed: ReturnType<typeof trivyJsonToInventory>;
  version: string | null;
}

/** Reads the licence pass's output `file` into the inventory; throws when it cannot. */
function readInventory(file: string, o: CollectDependenciesOptions): TrivyInventory {
  const output = readOutput(file);
  // The built-in excludes too: Trivy reports a .NET build's `bin/Debug/**/*.deps.json`, which
  // would otherwise count as out of scope on every scan after a build.
  const exclude = globMatcher([...BUILTIN_EXCLUDES, ...o.config.sources.exclude], true);
  const parsed = trivyJsonToInventory(output, o.root, { exclude, knownPaths: o.knownPaths });
  const v = (output as { Trivy?: { Version?: unknown } }).Trivy?.Version;
  const fits = typeof v === 'string' && v.length <= REPORT_BOUNDS.engineVersionChars;
  return { parsed, version: fits ? v : null };
}

/**
 * The inventory merged and capped (spec §2), with its warnings: one licence warning for the
 * parser's and the merge's drops together, and `DEPENDENCIES_TRUNCATED` when entries were cut.
 */
function finishInventory(parsed: ReturnType<typeof trivyJsonToInventory>): {
  entries: DependencyEntry[];
  warnings: NormalizeWarning[];
} {
  const stats = { licensesDropped: 0 };
  const merged = mergeDuplicates(parsed.entries, stats);
  const { entries, truncated } = capInventory(merged, MAX_DEPENDENCIES);
  const parsedLicenses = parsed.warnings.find((w) => w.code === 'DEPENDENCY_LICENSES_SKIPPED');
  const licensesDropped = (parsedLicenses?.count ?? 0) + stats.licensesDropped;
  const warnings = parsed.warnings.filter((w) => w !== parsedLicenses);
  if (licensesDropped > 0) warnings.push(licensesSkippedWarning(licensesDropped));
  if (truncated) {
    const dropped = merged.length - entries.length;
    warnings.push({
      code: 'DEPENDENCIES_TRUNCATED',
      message: `${dropped} of ${merged.length} dependencies were left out of the inventory (at most ${MAX_DEPENDENCIES} are reported, the direct ones first)`,
      count: dropped,
    });
  }
  return { entries, warnings };
}

/**
 * The Trivy licence pass of a scan (spec §1), after the analyzers: null when it is switched off
 * (`analyzers.trivy.enabled` or `licenses` false). It never fails the scan: a missing Trivy is a
 * skip (with `LICENSE_SCAN_FAILED` under `licenses: true`), a failure or a timeout is recorded on
 * the `trivy-licenses` engine with `LICENSE_SCAN_FAILED` or `LICENSE_SCAN_TIMEOUT`, and then no
 * inventory is reported. The process runs through the runner's helper with the analyzers'
 * environment rules (secrets stripped, search paths confined, the command's `dropEnv`).
 */
export async function collectDependencies(
  o: CollectDependenciesOptions,
): Promise<DependencyPass | null> {
  const enabled =
    o.force === true ? o.config.analyzers.trivy.enabled !== false : licensePassEnabled(o.config);
  if (!enabled) return null;
  const started = performance.now();
  const parentEnv = o.env ?? process.env;
  const settings = o.config.analyzers.trivy;
  const engine = (
    status: ReportEngine['status'],
    reason: string | null,
    version: string | null = null,
  ): ReportEngine => ({
    id: LICENSE_ENGINE_ID,
    kind: 'builtin',
    status,
    reason,
    version,
    durationMs: Math.max(0, Math.round(performance.now() - started)),
    rules: [],
  });
  const resolve =
    o.resolveBinary ?? ((name: string) => resolveOnPath(name, { root: o.root, env: parentEnv }));
  const trivy = resolve('trivy');
  if (trivy === null) {
    const reason = 'trivy is not installed (trivy on PATH or in the scanner image)';
    o.log.info(`${LICENSE_ENGINE_ID}: skipped (${reason})`);
    return {
      engine: engine('skipped', reason),
      warnings:
        settings.licenses === true || o.force === true
          ? [warning('LICENSE_SCAN_FAILED', `${reason}: no dependency inventory`)]
          : [],
    };
  }
  const failed = (reason: string, message: string): DependencyPass => {
    o.log.warn(`${LICENSE_ENGINE_ID}: failed (${reason})`);
    return {
      engine: engine('failed', reason),
      warnings: [warning('LICENSE_SCAN_FAILED', message)],
    };
  };

  const workDir = createWorkDir(LICENSE_ENGINE_ID, o.tempRoot);
  try {
    const analyzerEnv = confineAnalyzerEnv(sanitizeAnalyzerEnv(parentEnv), o.root);
    const ctx: AnalyzerContext = {
      root: o.root,
      config: o.config,
      languages: new Set(),
      files: [],
      workDir,
      log: o.log,
      dotnet: null,
      resolveBinary: resolve,
      repoBinary: () => null,
      env: analyzerEnv,
      exec: () => Promise.reject(new Error('the licence pass runs no helper command')),
    };
    const cacheDir = path.join(workDir, 'cache');
    mkdirSync(cacheDir);
    const run = licenseCommand(ctx, cacheDir);
    const spawn = o.runProcess ?? realRunProcess;
    const result = await withEmergencyCleanup(o.log, () =>
      spawn(
        {
          command: run.command,
          args: run.args,
          cwd: run.cwd,
          env: execEnv(
            parentEnv,
            {
              ...(run.env !== undefined && { env: run.env }),
              ...(run.dropEnv !== undefined && { dropEnv: run.dropEnv }),
            },
            o.root,
          ),
          timeoutMs: settings.licenseTimeoutSeconds * 1000,
        },
        o.log,
      ),
    );
    if (result.timedOut) {
      const reason = `timed out after ${settings.licenseTimeoutSeconds} s`;
      o.log.warn(`${LICENSE_ENGINE_ID}: timeout (${reason})`);
      return {
        engine: engine('timeout', reason),
        warnings: [
          warning(
            'LICENSE_SCAN_TIMEOUT',
            `the Trivy licence pass ${reason} (analyzers.trivy.licenseTimeoutSeconds): no dependency inventory`,
          ),
        ],
      };
    }
    if (result.spawnError !== undefined) {
      const reason = spawnFailureReason(result.spawnErrorCode);
      return failed(reason, `the Trivy licence pass could not run: ${reason}`);
    }
    if (result.exitCode === null || !run.okExitCodes.includes(result.exitCode)) {
      const reason = `exited with code ${result.exitCode ?? 'null'}`;
      // config.md §6: the tool's stderr stays in the log (the runner's `failureDetail` rule); the
      // report's warning is a fixed message.
      const first = stderrLines(result.stderr)[0];
      if (first !== undefined) o.log.warn(`${LICENSE_ENGINE_ID}: ${scrubLine(detailLine(first))}`);
      return failed(reason, `the Trivy licence pass ${reason}: no dependency inventory`);
    }
    let read: TrivyInventory;
    try {
      read = readInventory(run.sarifPath, o);
    } catch (err) {
      o.log.debug(
        `${LICENSE_ENGINE_ID}: output not read: ${err instanceof Error ? err.message : String(err)}`,
      );
      return failed('output could not be read', 'the Trivy licence pass output could not be read');
    }
    const { entries, warnings } = finishInventory(read.parsed);
    return { engine: engine('ok', null, read.version), entries, warnings };
  } catch (err) {
    o.log.debug(
      `${LICENSE_ENGINE_ID}: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
    );
    return failed('could not run', 'the Trivy licence pass could not run');
  } finally {
    releaseWorkDir(workDir, o.log);
  }
}
