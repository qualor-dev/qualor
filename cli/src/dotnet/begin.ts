import { randomBytes } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { QualorConfig } from '@qualor/shared';
import { isInside } from '../analyzers/binary';
import { loadSettings } from '../config/settings';
import { CliError, EXIT, type ExitCode } from '../errors';
import { VERSION } from '../index';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { installHook, msbuildUserDir } from './hook';
import { addLease, leaseDir, releaseLeases } from './leases';
import { createSession, removeSession, type SessionInfo, writeHookFailed } from './session';

const DEFAULT_ANALYZERS = '/opt/qualor/dotnet/analyzers';

/** config.md §4: absolute and outside the checkout (as written and after resolving links). */
function analyzerDir(env: Readonly<Record<string, string | undefined>>, root: string): string {
  const dir = env['QUALOR_DOTNET_ANALYZERS'] || DEFAULT_ANALYZERS;
  if (!path.isAbsolute(dir) || isInside(root, dir)) {
    throw new CliError(
      EXIT.USAGE,
      'QUALOR_DOTNET_ANALYZERS must be an absolute path outside the repository',
    );
  }
  return dir;
}

function bundledDlls(dir: string): string[] {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((n) => n.toLowerCase().endsWith('.dll'))
    .sort()
    .map((n) => path.join(dir, n))
    .filter((p) => {
      try {
        return lstatSync(p).isFile();
      } catch {
        return false;
      }
    });
}

export interface BeginDeps {
  now?: () => Date;
}

/**
 * Runs a cleanup step after a failure, logging (at debug level) rather than throwing when the
 * cleanup itself fails: a cleanup step must never replace or hide the original error.
 */
function cleanup(log: Logger, action: () => void): void {
  try {
    action();
  } catch (err) {
    log.debug(`qualor dotnet begin: cleanup failed: ${messageOf(err)}`);
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

type RoslynSettings = QualorConfig['analyzers']['roslyn'];

/** What the steps after the settings share. */
interface BeginRun {
  root: string;
  log: Logger;
  /** `analyzers.roslyn.enabled: true`: a failed step exits 3 instead of warning. */
  required: boolean;
}

/**
 * Under `auto`: leave `.qualor/dotnet/hook-failed` with the reason (so `end` reports the engine
 * unavailable, not skipped: final review R10), warn and exit 0. Under `enabled: true`: exit 3.
 * Used by every step below, after its own cleanup.
 */
function fail(run: BeginRun, reason: string, hint: string): ExitCode {
  if (run.required) throw new CliError(EXIT.ANALYZER_FAILED, reason);
  cleanup(run.log, () => writeHookFailed(run.root, reason));
  run.log.warn(`${reason}; ${hint}`);
  return EXIT.OK;
}

/**
 * The bundled analyzer DLLs of each family, warning when a family that is on has none. Task 4:
 * the bundled SonarAnalyzer.CSharp is its own family, next to Roslynator, under sonar/ of the same
 * directory. Off whenever bundledAnalyzers is (which gates every bundled analyzer), and also off on
 * its own with roslyn.sonarAnalyzer: false (config.md §6.1).
 */
function bundledAnalyzers(
  roslyn: RoslynSettings,
  dir: string,
  log: Logger,
): { roslynator: string[]; sonar: string[] } {
  const roslynator = roslyn.bundledAnalyzers ? bundledDlls(dir) : [];
  const sonarOn = roslyn.bundledAnalyzers && roslyn.sonarAnalyzer;
  const sonar = sonarOn ? bundledDlls(path.join(dir, 'sonar')) : [];
  if (roslyn.bundledAnalyzers && roslynator.length === 0) {
    // Not "the SDK's own rules only": the SonarAnalyzer family below may still be there.
    log.warn(`no bundled analyzers in ${dir}: the build runs without the bundled Roslynator`);
  }
  // config.md §6.1 step 4: each family's empty warning is independent of the other's.
  if (sonarOn && sonar.length === 0) {
    log.warn(
      `no bundled SonarAnalyzer in ${path.join(dir, 'sonar')}: the build runs without the bundled SonarAnalyzer.CSharp`,
    );
  }
  return { roslynator, sonar };
}

/**
 * Why the checkout path cannot carry the Roslyn log option, or null; a path the compiler cannot
 * write its logs to is only warned about.
 */
function checkoutPathProblem(realRoot: string, log: Logger): string | null {
  if (realRoot.includes(',')) {
    // csc's /errorlog:<path>,version=2.1 splits its argument on commas.
    log.warn(
      `the checkout path ${realRoot} contains a comma: the compiler cannot write its Roslyn logs there, so C# findings will be missing`,
    );
  }
  if (!realRoot.includes(';')) return null;
  // csc rejects /errorlog:<path>,version=2.1 with CS2046 when the path holds a semicolon, which
  // would break a build that passes without the hook.
  return `the checkout path ${realRoot} contains a semicolon: the compiler rejects it in its Roslyn log option (CS2046)`;
}

/** Step 1: session.json (removed again if it cannot be written); a failure's exit code, or null. */
function startSession(run: BeginRun, info: SessionInfo): ExitCode | null {
  try {
    createSession(run.root, info);
    return null;
  } catch (err) {
    if (err instanceof CliError) throw err;
    cleanup(run.log, () => removeSession(run.root));
    return fail(
      run,
      `cannot create the dotnet session in ${run.root}: ${messageOf(err)}`,
      'C# will not be analysed',
    );
  }
}

/**
 * Step 2, before the hook (final review R9): an `end` that removes the hook meanwhile counts this
 * lease when it checks again, and installs the hook again. A failure's exit code, or null.
 */
function recordLease(run: BeginRun, leases: string, id: string, now: Date): ExitCode | null {
  try {
    addLease(leases, id, run.root, now);
    return null;
  } catch (err) {
    cleanup(run.log, () => removeSession(run.root));
    if (err instanceof CliError) throw err;
    return fail(
      run,
      `cannot record the dotnet session lease in ${leases}: ${messageOf(err)}`,
      'C# will not be analysed (set QUALOR_MSBUILD_USER_DIR, or make the MSBuild user directory writable)',
    );
  }
}

/** Step 3: the MSBuild hook (session and lease removed again on failure); an exit code, or null. */
function installHookStep(
  run: BeginRun,
  userDir: string,
  lease: { leases: string; id: string; now: Date },
): ExitCode | null {
  try {
    installHook(userDir);
    return null;
  } catch (err) {
    cleanup(run.log, () => removeSession(run.root));
    cleanup(run.log, () => releaseLeases(lease.leases, lease.id, lease.now));
    if (err instanceof CliError) throw err;
    return fail(
      run,
      `cannot install the MSBuild hook in ${userDir}: ${messageOf(err)}`,
      'C# will not be analysed (set QUALOR_MSBUILD_USER_DIR, or make the MSBuild user directory writable)',
    );
  }
}

/** dotnet's own usage data is the CI job's to switch off: a warning while it is on. */
function warnDotnetTelemetry(env: CliIO['env'], log: Logger): void {
  const optOut = (env['DOTNET_CLI_TELEMETRY_OPTOUT'] ?? '').toLowerCase();
  if (optOut !== '1' && optOut !== 'true') {
    log.warn(
      'DOTNET_CLI_TELEMETRY_OPTOUT is not set to 1: dotnet sends usage data (set it in the CI job)',
    );
  }
}

/** `qualor dotnet begin` (config.md §6.1). */
export function runDotnetBegin(
  o: { config?: string },
  io: CliIO,
  log: Logger,
  deps: BeginDeps = {},
): ExitCode {
  const root = io.cwd;
  if (!existsSync(path.join(root, '.git'))) {
    throw new CliError(EXIT.USAGE, 'qualor dotnet begin runs at the root of the git work tree');
  }
  const settings = loadSettings({
    cwd: root,
    env: io.env,
    flags: o.config === undefined ? {} : { config: o.config },
    log,
  });
  const roslyn = settings.config.analyzers.roslyn;
  if (roslyn.enabled === false) {
    log.info('analyzers.roslyn is disabled in qualor.yml: no MSBuild hook installed');
    return EXIT.OK;
  }
  const userDir = msbuildUserDir(io.env);
  // config.md §4: QUALOR_MSBUILD_USER_DIR must be absolute (msbuildUserDir checks that) and
  // outside the checkout — a repository-controlled value must not be able to point the hook at
  // a path the merge request itself supplies.
  if (isInside(root, userDir)) {
    throw new CliError(
      EXIT.USAGE,
      'QUALOR_MSBUILD_USER_DIR must be an absolute path outside the repository',
    );
  }
  const dir = analyzerDir(io.env, root);
  const analyzers = bundledAnalyzers(roslyn, dir, log);
  const now = (deps.now ?? (() => new Date()))();
  const id = randomBytes(16).toString('hex');
  const run: BeginRun = { root, log, required: roslyn.enabled === true };

  // config.md §6.1 step 1: session.json's root is the real path of the repository root.
  const realRoot = realpathSync.native(root);
  const unusable = checkoutPathProblem(realRoot, log);
  if (unusable !== null) {
    return fail(run, unusable, 'C# will not be analysed; move the checkout to a path without ";"');
  }
  const started = startSession(run, {
    version: 1,
    id,
    root: realRoot,
    startedAt: now.toISOString(),
    cli: VERSION,
    analyzers,
  });
  if (started !== null) return started;
  const leases = leaseDir(userDir);
  const leased = recordLease(run, leases, id, now);
  if (leased !== null) return leased;
  const hooked = installHookStep(run, userDir, { leases, id, now });
  if (hooked !== null) return hooked;

  warnDotnetTelemetry(io.env, log);
  log.info(`MSBuild hook installed; build the project, then run qualor dotnet end`);
  return EXIT.OK;
}
