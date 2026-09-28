import { lstatSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { isUrl, type QualorConfig } from '@qualor/shared';
import { real, staysInside, within } from './binary';
import { gitleaksExtends, MAX_GITLEAKS_CONFIG_BYTES } from './gitleaks-config';
import { deadProxyEnv } from './offline';
import { shown } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** At most this many configs are followed through `[extend] path` (Gitleaks stops at depth 2). */
const MAX_EXTENDED_CONFIGS = 32;

type Env = Readonly<Record<string, string | undefined>>;

/** `gitleaks version` prints `8.30.1` (some builds `v8.30.1`). */
export function parseGitleaksVersion(stdout: string): string | null {
  return /v?(\d+\.\d+\.\d+\S*)/.exec(stdout.trim())?.[1] ?? null;
}

const exists = (file: string): boolean => {
  try {
    lstatSync(file);
    return true;
  } catch {
    return false;
  }
};

const isRegularFile = (file: string): boolean => {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
};

/**
 * `configFile` (config.md §3): a repository file. A URL or a path outside the repository (as
 * written or through a link) is a configuration error; a missing file is a skip reason.
 */
function resolveConfigFile(
  root: string,
  entry: string,
): string | { skip: string } | { error: string } {
  const name = `configFile ${shown(entry)}`;
  if (isUrl(entry)) return { error: `${name} is a URL (only repository files)` };
  const file = path.resolve(root, entry);
  if (!within(path.resolve(root), file) || !staysInside(root, file)) {
    return { error: `${name} is outside the repository` };
  }
  if (!exists(file)) return { skip: `${name} does not exist` };
  if (!isRegularFile(file)) return { skip: `${name} is not a regular file` };
  return file;
}

/**
 * A file Gitleaks reads from the repository root by itself (`.gitleaks.toml`, `.gitleaksignore`):
 * null when there is none, else its path, or an error when it links out of the repository or is
 * not a regular file (a FIFO would hang Gitleaks).
 */
function rootFile(root: string, name: string): string | { error: string } | null {
  const file = path.join(root, name);
  if (!exists(file)) return null;
  if (!staysInside(root, file)) return { error: `${name} is outside the repository` };
  if (!isRegularFile(file)) return { error: `${name} is not a regular file` };
  return file;
}

/**
 * Ruling V4 for Gitleaks: a repository config may extend only other repository files. Every
 * `[extend] path` (Gitleaks resolves it against the working directory, the repository root) is
 * followed; an absolute path, a URL, a path outside the repository or a missing file is an error,
 * and so is a config this check cannot read with certainty.
 */
function checkExtendChain(root: string, top: string): string | null {
  const rel = (file: string) => shown(path.relative(root, file).split(path.sep).join('/'));
  const queue = [top];
  const visited = new Set<string>();
  while (queue.length > 0) {
    const file = queue.shift() as string;
    const key = real(file);
    if (visited.has(key)) continue;
    visited.add(key);
    if (visited.size > MAX_EXTENDED_CONFIGS) {
      return `Gitleaks config ${rel(top)} extends more than ${MAX_EXTENDED_CONFIGS} configs`;
    }
    const name = `Gitleaks config ${rel(file)}`;
    let bytes: Buffer;
    try {
      if (statSync(file).size > MAX_GITLEAKS_CONFIG_BYTES) {
        return `${name} is larger than ${MAX_GITLEAKS_CONFIG_BYTES / 1024 / 1024} MiB`;
      }
      bytes = readFileSync(file);
    } catch {
      return `${name} cannot be read`;
    }
    const parsed = gitleaksExtends(bytes);
    if ('error' in parsed) return `${name} ${parsed.error}`;
    for (const target of parsed.paths) {
      if (target === '') continue;
      const bad = (why: string) => `${name}: extend.path "${shown(target)}" ${why}`;
      if (isUrl(target)) return bad('is a URL (only repository files)');
      if (
        path.isAbsolute(target) ||
        path.posix.isAbsolute(target) ||
        path.win32.isAbsolute(target)
      ) {
        return bad('is an absolute path (only repository files)');
      }
      const next = path.resolve(root, target);
      if (!within(path.resolve(root), next)) return bad('is outside the repository');
      if (!exists(next)) return bad('does not exist');
      if (!staysInside(root, next)) return bad('is outside the repository');
      if (!isRegularFile(next)) return bad('is not a regular file');
      queue.push(next);
    }
  }
  return null;
}

const nonEmpty = (v: string | undefined): boolean => v !== undefined && v !== '';

/**
 * The repository config Gitleaks will load: `configFile`, else (when the CI names no config in
 * `GITLEAKS_CONFIG`/`GITLEAKS_CONFIG_TOML`) the root `.gitleaks.toml`; null for none.
 */
function repoConfig(
  root: string,
  config: QualorConfig,
  env: Env,
): string | { skip: string } | { error: string } | null {
  const configFile = config.analyzers.gitleaks.configFile;
  if (configFile !== null) return resolveConfigFile(root, configFile);
  if (nonEmpty(env['GITLEAKS_CONFIG']) || nonEmpty(env['GITLEAKS_CONFIG_TOML'])) return null;
  return rootFile(root, '.gitleaks.toml');
}

/**
 * The Gitleaks configuration errors of config.md §6 (exit 2). The config Gitleaks will load is,
 * in its own order: `configFile` (passed as `--config`), else `GITLEAKS_CONFIG` or
 * `GITLEAKS_CONFIG_TOML` from the CI environment (the CI's choice, not checked), else a
 * `.gitleaks.toml` at the repository root. A repository config and every config it extends must
 * stay inside the repository; `.gitleaksignore` (Gitleaks reads it from the root) must too.
 *
 * Other `.gitleaks.*` files at the root are ignored, not refused: when `.gitleaks.toml` exists,
 * Gitleaks 8.30 lets viper search `.gitleaks.<ext>` (json first) and parses the first match as
 * TOML, but `prepare` always passes the checked file itself as `--config`, which stops the search.
 * Refusing them instead would only turn a harmless sibling (a `.gitleaks.json` for another tool)
 * into a failed scan, and would depend on viper's list of extensions.
 */
export function checkGitleaksConfig(
  root: string,
  config: QualorConfig,
  env: Env = {},
): string | null {
  const top = repoConfig(root, config, env);
  if (top !== null && typeof top !== 'string' && 'error' in top) return top.error;
  if (typeof top === 'string') {
    const problem = checkExtendChain(root, top);
    if (problem !== null) return problem;
  }
  const ignore = rootFile(root, '.gitleaksignore');
  return ignore !== null && typeof ignore !== 'string' ? ignore.error : null;
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  // `qualor scan` stops with exit 2 on these before any analyzer runs (checkConfig); this is
  // the same check for any other caller of the runner.
  const problem = checkGitleaksConfig(ctx.root, ctx.config, ctx.env);
  if (problem !== null) return { skip: problem };
  // The checked repository config is always named explicitly, so Gitleaks never searches the
  // root for another `.gitleaks.<ext>` it would load unchecked (fix round 1 of tasks 5-6).
  const configArgs: string[] = [];
  const file = repoConfig(ctx.root, ctx.config, ctx.env);
  if (file !== null && typeof file !== 'string')
    return 'skip' in file ? file : { skip: file.error };
  if (file !== null) configArgs.push('--config', file);
  const gitleaks = ctx.resolveBinary('gitleaks');
  if (gitleaks === null) {
    return { unavailable: 'Gitleaks is not installed (gitleaks on PATH or in the scanner image)' };
  }
  // Gitleaks writes a placeholder version (v8.0.0) into its SARIF, so ask the binary itself.
  const probe = await ctx.exec(gitleaks, ['version'], { timeoutMs: 30_000 });
  const out = path.join(ctx.workDir, 'gitleaks.sarif');
  return {
    run: {
      command: gitleaks,
      args: [
        // The working tree as it is (not the git history): the same files every other engine sees.
        'dir',
        '.',
        '--report-format',
        'sarif',
        '--report-path',
        out,
        ...configArgs,
        '--no-banner',
        '--no-color',
        // Never `-v`: verbose output prints every secret. At `error` level nothing a scan finds
        // is logged; the SARIF file (secrets in clear text) stays in the private work directory.
        '--log-level',
        'error',
        // Leaks found still exit 0, so any non-zero exit is a real failure (a bad config, …).
        '--exit-code',
        '0',
      ],
      cwd: ctx.root,
      env: deadProxyEnv(),
      sarifPath: out,
      okExitCodes: [0],
      version: probe.exitCode === 0 ? parseGitleaksVersion(probe.stdout) : null,
    },
  };
}

/** Languages: [] — secrets live in any file, so Gitleaks always runs (config.md §3: enabled true). */
export const gitleaksAnalyzer: Analyzer = {
  id: 'gitleaks',
  languages: [],
  prepare,
  checkConfig: checkGitleaksConfig,
};
