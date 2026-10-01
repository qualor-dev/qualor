import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  GO_MIN_VERSION,
  GO_VERSION,
  GOSEC_VERSION,
  goVersionSupported,
  gosecVersionSupported,
  STATICCHECK_VERSION,
  staticcheckVersionSupported,
} from '@qualor/shared';
import type { ScopeFile } from '../discovery/discover';
import type { Logger } from '../log';
import { isInside } from './binary';
import { GO_KEPT_ENV, goEnv, goModuleCache, planGoModules, type GoModulePlan } from './go-modules';
import { detailLine, shown, stderrLines } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

export type GoTool = 'staticcheck' | 'govet' | 'gosec';

/** Where the qualor/scanner image installs Qualor's Go runner (config.md §4 QUALOR_GO_DIR). */
export const DEFAULT_GO_DIR = '/opt/qualor/go';

/**
 * The runner script, or why it cannot run. A missing install is a skip (an image-bundled resource
 * absent on a plain host, ruling G6); a relative or in-repository QUALOR_GO_DIR is unavailable (a
 * merge request must never point it at its own code).
 */
export function goRunnerScript(
  ctx: AnalyzerContext,
): { script: string } | { skip: string } | { unavailable: string } {
  const dir = ctx.env['QUALOR_GO_DIR'] || DEFAULT_GO_DIR;
  if (!path.isAbsolute(dir) || isInside(ctx.root, dir)) {
    return { unavailable: 'QUALOR_GO_DIR must be an absolute path outside the repository' };
  }
  const script = path.join(dir, 'run.mjs');
  if (!existsSync(script))
    return { skip: "Qualor's Go runner is not installed (qualor/scanner image)" };
  return { script };
}

/** `go version go1.27.1 linux/amd64` → `1.27.1` (`1.28rc1` too; `devel` builds: null). */
export function parseGoVersion(stdout: string): string | null {
  return (
    /^go version go(\d+\.\d+(?:\.\d+)?(?:(?:rc|beta)\d+)?)\s/.exec(`${stdout.trim()} `)?.[1] ?? null
  );
}

/** `staticcheck 2026.2.1 (0.8.1)` → `2026.2.1`. */
export function parseStaticcheckVersion(stdout: string): string | null {
  return /^staticcheck (\d+\.\d+\.\d+)\b/.exec(stdout.trim())?.[1] ?? null;
}

/** gosec's `Version: 2.29.0` line. */
export function parseGosecVersion(stdout: string): string | null {
  return /^Version: (\d+\.\d+\.\d+)$/m.exec(stdout)?.[1] ?? null;
}

const FATAL = 'go: fatal: ';
const WARNING = 'go: warning: ';
/**
 * The runner's MAX_WARNINGS (tools/analyzers/golang/run.mjs, dependency-free, so it cannot import
 * this; tools/analyzers/golang/run.test.ts checks the two agree).
 */
export const GO_RUNNER_MAX_WARNINGS = 20;
/** Its warnings plus its one "N more" line. */
const MAX_LOGGED_WARNINGS = GO_RUNNER_MAX_WARNINGS + 1;

/** Why the runner failed (ruling F8): its `go: fatal:` line, bounded; for the log only. */
export function goFailureDetail(stderr: string): string | null {
  const line = stderrLines(stderr).findLast((l) => l.startsWith(FATAL));
  return line === undefined ? null : detailLine(line.slice(FATAL.length));
}

/** The runner's own warnings (modules and packages not analysed), bounded; never other stderr. */
export function goWarnings(stderr: string): string[] {
  return stderrLines(stderr)
    .filter((l) => l.startsWith(WARNING))
    .slice(0, MAX_LOGGED_WARNINGS)
    .map((l) => detailLine(l.slice(WARNING.length)));
}

function logSummary(log: Logger, tool: GoTool, stdout: string): void {
  const last = stdout
    .split('\n')
    .filter((l) => l.trim() !== '')
    .at(-1);
  if (last === undefined) return;
  try {
    const s = JSON.parse(last) as Record<string, unknown>;
    log.debug(
      `${tool}: ${String(s['modules'])} module(s), ${String(s['packages'])} package(s) analysed, ${String(s['notLoaded'])} not loaded, ${String(s['results'])} result(s), ${String(s['outOfScope'])} outside the scope`,
    );
  } catch {
    // The SARIF and the exit code already decide the run; a missing summary only loses a debug line.
  }
}

function notInstalled(ctx: AnalyzerContext, name: string): string {
  const base = `${name} is not installed (${name} on PATH or in the qualor/scanner image)`;
  return ctx.repoBinary(name) === null
    ? base
    : `${base}; the repository's own ${name} is never run`;
}

/**
 * Ruling G9-15: a version probe keeps the CI's environment (ctx.exec) but never its Go toolchain
 * choice: a CI-set GOTOOLCHAIN=go1.xx, a go env file or GOFLAGS would make `go version` download
 * and run another toolchain.
 */
const PROBE_ENV: Readonly<Record<string, string>> = Object.freeze({
  GOTOOLCHAIN: 'local',
  GOENV: 'off',
  GOFLAGS: '',
});

async function probe(
  ctx: AnalyzerContext,
  binary: string,
  args: readonly string[],
  parse: (stdout: string) => string | null,
): Promise<string | null> {
  const r = await ctx.exec(binary, args, {
    timeoutMs: 30_000,
    cwd: ctx.workDir,
    env: PROBE_ENV,
  });
  return r.exitCode === 0 ? parse(r.stdout) : null;
}

interface ScanPlan {
  goVersion: string;
  plan: GoModulePlan;
  cacheLogged: boolean;
}

/**
 * One module plan per scan, shared by the three Go engines: runAnalyzers hands every analyzer the
 * same `files` array, so it keys the plan. Each left-out module and the Go files outside every
 * module are logged once, when the plan is made; `logCache()` is true only for the first engine
 * that asks, so a refused module cache is logged once too. Planning is synchronous, so engines
 * preparing in parallel never plan twice.
 */
const SCAN_PLANS = new WeakMap<readonly ScopeFile[], ScanPlan>();

function scanPlan(
  ctx: AnalyzerContext,
  goVersion: string,
): { plan: GoModulePlan; logCache: () => boolean } {
  let entry = SCAN_PLANS.get(ctx.files);
  if (entry === undefined || entry.goVersion !== goVersion) {
    const plan = planGoModules(ctx.root, ctx.files, goVersion);
    for (const s of plan.skipped) {
      const name = s.rel === '' ? 'the root module' : shown(s.rel);
      ctx.log.warn(`go: ${detailLine(`${name} is not analysed: ${s.reason}`)}`);
    }
    if (plan.outside > 0) {
      ctx.log.warn(
        `go: ${plan.outside} Go file(s) outside every module (no go.mod above them) are not analysed`,
      );
    }
    entry = { goVersion, plan, cacheLogged: false };
    SCAN_PLANS.set(ctx.files, entry);
  }
  const e = entry;
  return {
    plan: e.plan,
    logCache: () => {
      if (e.cacheLogged) return false;
      e.cacheLogged = true;
      return true;
    },
  };
}

async function prepareGo(ctx: AnalyzerContext, tool: GoTool): Promise<Preparation> {
  const goFiles = ctx.files.filter((f) => f.language === 'go');
  if (goFiles.length === 0) return { skip: 'no Go file in scope' };
  const runner = goRunnerScript(ctx);
  if (!('script' in runner)) return runner;
  const node = ctx.resolveBinary('node');
  if (node === null) return { unavailable: 'the Go analyzers need node on PATH' };
  const go = ctx.resolveBinary('go');
  if (go === null) return { skip: notInstalled(ctx, 'go') };
  const goVersion = await probe(ctx, go, ['version'], parseGoVersion);
  if (goVersion === null) return { unavailable: '`go version` printed no version' };
  if (!goVersionSupported(goVersion)) {
    return {
      skip: `Go ${goVersion} is not supported: the Go analyzers need Go ${GO_MIN_VERSION} or newer (the qualor/scanner image has Go ${GO_VERSION})`,
    };
  }
  let toolPath = go;
  let version = goVersion;
  if (tool !== 'govet') {
    const bin = ctx.resolveBinary(tool);
    if (bin === null) return { skip: notInstalled(ctx, tool) };
    const parse = tool === 'staticcheck' ? parseStaticcheckVersion : parseGosecVersion;
    const v = await probe(ctx, bin, ['-version'], parse);
    if (v === null) return { unavailable: `\`${tool} -version\` printed no version` };
    const pinned = tool === 'staticcheck' ? STATICCHECK_VERSION : GOSEC_VERSION;
    const supported =
      tool === 'staticcheck' ? staticcheckVersionSupported(v) : gosecVersionSupported(v);
    if (!supported) {
      const minor = pinned.split('.').slice(0, 2).join('.');
      return {
        skip: `${tool} ${v} is not supported: this Qualor runs ${tool} ${minor}.x (the qualor/scanner image's ${pinned})`,
      };
    }
    toolPath = bin;
    version = v;
  }
  const { plan, logCache } = scanPlan(ctx, goVersion);
  if (plan.modules.length === 0) {
    const first = plan.skipped[0];
    return {
      skip:
        first === undefined
          ? 'no Go module in scope: Qualor analyses Go modules (a go.mod above the files)'
          : `no Go module Qualor can analyse: ${first.reason}`,
    };
  }
  const cache = goModuleCache(ctx.env, ctx.root, ctx.workDir);
  if (cache.warning !== null && logCache()) ctx.log.warn(`go: ${cache.warning}`);
  const out = path.join(ctx.workDir, `${tool}.sarif`);
  const specPath = path.join(ctx.workDir, `${tool}-spec.json`);
  writeFileSync(
    specPath,
    JSON.stringify({
      tool,
      toolPath,
      go,
      version,
      root: ctx.root,
      workDir: ctx.workDir,
      out,
      files: goFiles.map((f) => f.path),
      modules: plan.modules.map((m) => ({ dir: m.dir, rel: m.rel })),
      gosecExclude: tool === 'gosec' ? [...ctx.config.analyzers.gosec.exclude] : [],
    }),
  );
  const own = goEnv({
    workDir: ctx.workDir,
    go,
    moduleCache: cache.dir,
    path: ctx.env['PATH'] ?? ctx.env['Path'],
  });
  return {
    run: {
      command: node,
      args: [runner.script, '--spec', specPath],
      cwd: ctx.workDir,
      env: own,
      dropEnv: (name) => !Object.hasOwn(own, name) && !GO_KEPT_ENV.has(name.toUpperCase()),
      sarifPath: out,
      // 2: a fatal problem (`go: fatal: …`); every per-module problem is a warning (run.mjs).
      okExitCodes: [0],
      version,
      transform: (output, stdout) => {
        logSummary(ctx.log, tool, stdout);
        return output;
      },
      failureDetail: (_code, stderr) => goFailureDetail(stderr),
      configWarnings: (stderr) => goWarnings(stderr),
    },
  };
}

const goAnalyzer = (id: GoTool): Analyzer => ({
  id,
  languages: ['go'],
  ruleLanguages: ['go'],
  prepare: (ctx) => prepareGo(ctx, id),
});

export const staticcheckAnalyzer: Analyzer = goAnalyzer('staticcheck');
export const govetAnalyzer: Analyzer = goAnalyzer('govet');
export const gosecAnalyzer: Analyzer = goAnalyzer('gosec');
