import { randomBytes } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { isInside } from '../analyzers/binary';
import { loadSettings } from '../config/settings';
import { CliError, EXIT, type ExitCode } from '../errors';
import { VERSION } from '../index';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { installHook, msbuildUserDir } from './hook';
import { addLease, leaseDir, releaseLeases } from './leases';
import { createSession, removeSession, writeHookFailed } from './session';

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
    log.debug(
      `qualor dotnet begin: cleanup failed: ${err instanceof Error ? err.message : String(err)}`,
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
  const analyzers = roslyn.bundledAnalyzers ? bundledDlls(dir) : [];
  if (roslyn.bundledAnalyzers && analyzers.length === 0) {
    log.warn(`no bundled analyzers in ${dir}: the build reports the .NET SDK's own rules only`);
  }
  const now = (deps.now ?? (() => new Date()))();
  const id = randomBytes(16).toString('hex');

  /**
   * Under `auto`: leave `.qualor/dotnet/hook-failed` with the reason (so `end` reports the engine
   * unavailable, not skipped: final review R10), warn and exit 0. Under `enabled: true`: exit 3.
   * Used by every step below, after its own cleanup.
   */
  const fail = (reason: string, hint: string): ExitCode => {
    if (roslyn.enabled === true) throw new CliError(EXIT.ANALYZER_FAILED, reason);
    cleanup(log, () => writeHookFailed(root, reason));
    log.warn(`${reason}; ${hint}`);
    return EXIT.OK;
  };

  // config.md §6.1 step 1: session.json's root is the real path of the repository root.
  const realRoot = realpathSync.native(root);
  if (realRoot.includes(',')) {
    // csc's /errorlog:<path>,version=2.1 splits its argument on commas.
    log.warn(
      `the checkout path ${realRoot} contains a comma: the compiler cannot write its Roslyn logs there, so C# findings will be missing`,
    );
  }
  try {
    createSession(root, {
      version: 1,
      id,
      root: realRoot,
      startedAt: now.toISOString(),
      cli: VERSION,
      analyzers,
    });
  } catch (err) {
    if (err instanceof CliError) throw err;
    cleanup(log, () => removeSession(root));
    return fail(
      `cannot create the dotnet session in ${root}: ${err instanceof Error ? err.message : String(err)}`,
      'C# will not be analysed',
    );
  }

  // Step 2, before the hook (final review R9): an `end` that removes the hook meanwhile counts
  // this lease when it checks again, and installs the hook again.
  const leases = leaseDir(userDir);
  try {
    addLease(leases, id, root, now);
  } catch (err) {
    cleanup(log, () => removeSession(root));
    if (err instanceof CliError) throw err;
    return fail(
      `cannot record the dotnet session lease in ${leases}: ${err instanceof Error ? err.message : String(err)}`,
      'C# will not be analysed (set QUALOR_MSBUILD_USER_DIR, or make the MSBuild user directory writable)',
    );
  }

  try {
    installHook(userDir);
  } catch (err) {
    cleanup(log, () => removeSession(root));
    cleanup(log, () => releaseLeases(leases, id, now));
    if (err instanceof CliError) throw err;
    return fail(
      `cannot install the MSBuild hook in ${userDir}: ${err instanceof Error ? err.message : String(err)}`,
      'C# will not be analysed (set QUALOR_MSBUILD_USER_DIR, or make the MSBuild user directory writable)',
    );
  }

  const optOut = (io.env['DOTNET_CLI_TELEMETRY_OPTOUT'] ?? '').toLowerCase();
  if (optOut !== '1' && optOut !== 'true') {
    log.warn(
      'DOTNET_CLI_TELEMETRY_OPTOUT is not set to 1: dotnet sends usage data (set it in the CI job)',
    );
  }
  log.info(`MSBuild hook installed; build the project, then run qualor dotnet end`);
  return EXIT.OK;
}
