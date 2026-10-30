import { realpathSync } from 'node:fs';
import path from 'node:path';
import { locateQualorPack } from '../analyzers/qualor';
import { readRoslynLogs, mergeRoslynLogs } from '../analyzers/roslyn-logs';
import type { DotnetRun, TaintRun } from '../analyzers/types';
import type { ScanFlags } from '../args';
import { loadSettings } from '../config/settings';
import { scanTag } from '../git/scm';
import type { ExitCode } from '../errors';
import type { CliIO } from '../io';
import { silentLogger, type Logger } from '../log';
import { runScan, type ScanDeps } from '../scan/run';
import { runTaintEngine, taintBudgets, type TaintEngineOptions } from './engine';
import { installHook, msbuildUserDir, removeHook } from './hook';
import { leaseDir, releaseLeases } from './leases';
import {
  isFresh,
  listLogs,
  readHookFailed,
  readProjectRecords,
  readSession,
  removeSession,
  SESSION_DIR,
  type SessionInfo,
} from './session';

/**
 * The session at `root`, but only when it is this checkout's own (config.md §6.1): its `root`
 * field must resolve, after symlinks, to the same real path as `root` itself. A session.json
 * copied from elsewhere, or left by a checkout that was since moved or replaced, names another
 * directory — trusting it would release another session's lease by id, or read its projects as
 * though this build had produced them, while that other session may still be running.
 */
function ownSession(root: string): SessionInfo | null {
  const session = readSession(root);
  if (session === null) return null;
  try {
    if (realpathSync.native(session.root) !== realpathSync.native(root)) return null;
  } catch {
    return null;
  }
  return session;
}

/** Steps 3–4 of config.md §6.1 `end`: what the build left, as the roslyn engine sees it. */
export function collectDotnetRun(
  root: string,
  log: Logger,
  warn: (code: string, message: string) => void,
): DotnetRun {
  const failed = readHookFailed(root);
  if (failed !== null) return { kind: 'hook-failed', reason: failed };
  if (ownSession(root) === null) return { kind: 'no-session' };
  const records = readProjectRecords(root, log);
  if (records.length === 0) return { kind: 'no-build' };
  const stale = records.filter((r) => !isFresh(r.log, root));
  if (stale.length > 0) {
    const names = stale
      .slice(0, 5)
      .map((r) => `${r.project} (${r.targetFramework})`)
      .join(', ');
    const more = stale.length > 5 ? ` and ${stale.length - 5} more` : '';
    warn(
      'ROSLYN_PROJECT_NOT_ANALYZED',
      `${stale.length} C# project build(s) wrote no Roslyn log in this session: ${names}${more}; use dotnet build --no-incremental`,
    );
  }
  const fresh = listLogs(root).filter((f) => isFresh(f, root));
  if (fresh.length === 0) return { kind: 'not-compiled' };
  const { logs, unreadable } = readRoslynLogs(fresh, log);
  if (unreadable > 0)
    log.warn(`roslyn: ${unreadable} log(s) could not be read (see the debug log)`);
  if (logs.length === 0) return { kind: 'not-compiled' };
  const merged = mergeRoslynLogs(logs);
  log.debug(
    `roslyn: ${logs.length} log(s), ${merged.results} result(s), ${merged.duplicates} repeat(s) across target frameworks dropped`,
  );
  return { kind: 'collected', merged, taint: null };
}

/**
 * config.md §6.1 `end` step 2: releases lease `id` and prunes stale ones; when no live lease is
 * left, removes the hook (only Qualor's), then counts again. A job's `begin` records its lease
 * before it installs the hook, so a live lease that appeared meanwhile belongs to a job whose
 * hook this removal may just have deleted: the hook is installed again (final review R9).
 * `remove` is `removeHook`, replaceable by a test to interleave such a `begin`.
 */
export function releaseHook(
  userDir: string,
  id: string,
  now: Date,
  log: Logger,
  remove: (userDir: string) => boolean = removeHook,
): void {
  const dir = leaseDir(userDir);
  if (releaseLeases(dir, id, now) > 0) return;
  if (!remove(userDir)) return;
  log.info('MSBuild hook removed');
  if (releaseLeases(dir, '', now) > 0) {
    log.debug('qualor dotnet: another session began meanwhile; MSBuild hook reinstalled');
    installHook(userDir);
  }
}

/**
 * config.md §6.1 `end` step 2 for the checkout at `root`, shared by `end` and `abort`: it runs
 * session or not — an empty id matches no lease, so without a session of our own here only
 * leases older than 24 hours are pruned, and the hook this runner's other live sessions still
 * need is left alone. A failure is a warning: the hook is inert outside a live session.
 */
export function releaseCheckout(root: string, io: CliIO, log: Logger): void {
  const session = ownSession(root);
  try {
    releaseHook(msbuildUserDir(io.env), session?.id ?? '', new Date(), log);
  } catch (err) {
    log.warn(
      `could not remove the MSBuild hook: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

export interface DotnetEndDeps extends ScanDeps {
  /** Runs Qualor's Roslyn taint engine (tests replace it). */
  runTaint?: (o: TaintEngineOptions) => Promise<TaintRun>;
}

/**
 * 6B-C# R, spec §4.2: the taint engine's run on this session's compiler inputs, while they are
 * still there; null when it is not attempted (the qualor engine is disabled, or no rules pack is
 * installed, so the OpenGrep C# rules do not run either). A fallback is logged with its detail;
 * the report's warning names only the reason (R-4).
 */
async function runSessionTaint(
  root: string,
  flags: ScanFlags,
  io: CliIO,
  log: Logger,
  runTaint: (o: TaintEngineOptions) => Promise<TaintRun>,
): Promise<TaintRun | null> {
  try {
    const { config } = loadSettings({ cwd: root, env: io.env, flags, log: silentLogger });
    if (config.analyzers.qualor.enabled === false) return null;
  } catch {
    // The scan reports the configuration problem itself.
  }
  let taint: TaintRun;
  try {
    const pack = locateQualorPack(root, io.env);
    if (!('manifest' in pack)) return null;
    taint = await runTaint({
      root,
      pack,
      sessionDir: path.join(root, ...SESSION_DIR.split('/')),
      env: io.env,
      ...taintBudgets(io.env, (message) => log.warn(message), {
        info: (message) => log.info(message),
      }),
      log,
    });
  } catch (err) {
    // R-4 (fix round 1, I1): whatever goes wrong here, OpenGrep runs and the scan goes on.
    const message = err instanceof Error ? err.message : String(err);
    taint = { kind: 'fallback', reason: 'crash', detail: message.split(/\r?\n/)[0] ?? '' };
  }
  if (taint.kind === 'ok') {
    log.info("Qualor's Roslyn taint engine analysed the C# files");
  } else {
    log.warn(
      `Qualor's Roslyn taint engine did not run (${taint.reason}: ${taint.detail}); the OpenGrep C# rules run in its place`,
    );
  }
  return taint;
}

/** Whether this scan is of a tag (`--tag` or CI's tag pipeline): a version, not an analysis. */
function isTagScan(root: string, flags: ScanFlags, io: CliIO): boolean {
  try {
    const { ci } = loadSettings({ cwd: root, env: io.env, flags, log: silentLogger });
    return scanTag(flags, ci) !== null;
  } catch {
    // The scan reports the configuration problem itself.
    return false;
  }
}

/**
 * `qualor dotnet end` (config.md §6.1): hook and lease first, then the logs and the taint engine
 * (6B-C# R) on what the build left, then the session is deleted and the scan runs.
 */
export async function runDotnetEnd(
  flags: ScanFlags,
  io: CliIO,
  log: Logger,
  deps: DotnetEndDeps = {},
): Promise<ExitCode> {
  const { runTaint = runTaintEngine, ...scanDeps } = deps;
  const root = io.cwd;
  releaseCheckout(root, io, log);
  const warnings: { code: string; message: string }[] = [];
  let run: DotnetRun;
  try {
    if (isTagScan(root, flags, io)) {
      // A tag scan records a version (the dependency list): no analyzer reads the build's logs.
      run = { kind: 'no-session' };
    } else {
      run = collectDotnetRun(root, log, (code, message) => {
        log.warn(message);
        warnings.push({ code, message });
      });
      if (run.kind === 'collected') {
        run = { ...run, taint: await runSessionTaint(root, flags, io, log, runTaint) };
      }
    }
  } finally {
    removeSession(root);
  }
  return runScan(flags, io, log, { ...scanDeps, dotnet: run, extraWarnings: warnings });
}
