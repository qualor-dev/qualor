import {
  existsSync,
  lstatSync,
  opendirSync,
  readdirSync,
  readFileSync,
  statSync,
  type Stats,
} from 'node:fs';
import path from 'node:path';
import { BUILTIN_EXCLUDES, isUrl, type NormalizeWarning, type QualorConfig } from '@qualor/shared';
import { parseAllDocuments } from 'yaml';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { real, staysInside, within } from './binary';
import { type FileLockOptions, withFileLock } from './file-lock';
import type { Logger } from '../log';
import { deadProxyEnv } from './offline';
import { shown } from './reason';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/**
 * Where the `qualor/scanner` image puts the rule pack that `configs: [qualor-default]` names. Which
 * rules it holds is still open (the community Semgrep rules may not be bundled); the CLI
 * itself ships no rules, so without the image `qualor-default` is simply not available.
 */
const DEFAULT_SEMGREP_RULES_DIR = '/opt/qualor/rules/semgrep';

/** More `--config` arguments than this is a configuration error (a bounded command line). */
export const MAX_SEMGREP_CONFIGS = 64;
/** A rule file larger than this is not read (rule files are a few KiB). */
export const MAX_RULE_FILE_BYTES = 4 * 1024 * 1024;
/** Rule files and directory entries examined below one config directory. */
const MAX_RULE_FILES = 10_000;
const MAX_ENTRIES_CHECKED = 1_000_000;
/** Anchored aliases a rule file may expand (a YAML "billion laughs" is refused). */
const MAX_ALIAS_COUNT = 1_000;

type Flavour = 'opengrep' | 'semgrep';

/**
 * Flags that keep both tools offline and the rule ids stable (ruling A3). Semgrep sends usage
 * metrics unless `--metrics=off`; OpenGrep has no metrics (and rejects the flag). Neither checks
 * for a new version with `--disable-version-check`.
 */
export function offlineFlags(flavour: Flavour): string[] {
  return [
    ...(flavour === 'semgrep' ? ['--metrics=off'] : []),
    '--disable-version-check',
    '--no-rewrite-rule-ids',
    '--quiet',
  ];
}

/**
 * Plan 6B-1 (config.md §6): OpenGrep and Semgrep read `SEMGREP_*` and `OPENGREP_*` variables behind
 * the command line's back. Verified with OpenGrep 1.30.0: `SEMGREP_BASELINE_COMMIT` and
 * `SEMGREP_BASELINE_REF` report only findings new since that commit, `SEMGREP_TIMEOUT` changes the
 * per-file timeout, `SEMGREP_LOG_FILE` writes a log wherever it names. None reaches the tool.
 */
export function isOpengrepVariable(name: string): boolean {
  const upper = name.toUpperCase();
  return upper.startsWith('SEMGREP_') || upper.startsWith('OPENGREP_');
}

/**
 * The exclusive group (`AnalyzerCommand.exclusive`) of every OpenGrep run: the semgrep and qualor
 * engines. OpenGrep 1.30.0 is a self-extracting launcher that unpacks about 250 MB into
 * `$HOME/.cache/opengrep/<version>/` on its first run; launchers unpacking there at the same time
 * crash with SIGBUS (probed in a fresh qualor/scanner container: 3 or 4 at once fail in most
 * containers). One at a time, the first unpacks and the next finds the cache complete. This keeps
 * the runs of one scan apart; `warmOpengrep` keeps separate `qualor scan` processes apart.
 */
export const OPENGREP_GROUP = 'opengrep';

/**
 * The cache root OpenGrep's launcher unpacks into (`<root>/v<version>/`): Nuitka's `{CACHE_DIR}`
 * (its onefile bootstrap, HelpersFilesystemPaths.c) is `$XDG_CACHE_HOME` when that starts with
 * `/`, else `$HOME/.cache`, on Linux and macOS alike (not `~/Library/Caches`), and the local
 * application data folder on Windows. Null without one (the lock is then skipped).
 */
export function opengrepCacheDir(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform = process.platform,
): string | null {
  const absolute = (name: string): string | null => {
    const value = env[name];
    return value !== undefined && path.isAbsolute(value) ? value : null;
  };
  if (platform === 'win32') {
    const local = absolute('LOCALAPPDATA');
    return local === null ? null : path.join(local, 'opengrep');
  }
  const xdg = absolute('XDG_CACHE_HOME');
  if (xdg !== null) return path.join(xdg, 'opengrep');
  const home = absolute('HOME');
  return home === null ? null : path.join(home, '.cache', 'opengrep');
}

/** A launch that unpacks the cache when it is cold, and finds it complete when it is warm. */
export const OPENGREP_WARM_ARGS: readonly string[] = ['--version', '--disable-version-check'];
/** Unpacking takes a few seconds; well below the lock's stale age (`withFileLock`). */
export const OPENGREP_WARM_TIMEOUT_MS = 120_000;

const WARM_FAILED = "OpenGrep's first launch, which unpacks it,";

/** Why the warm-up launch failed, as a fixed text (never the tool's own output), or null. */
function warmFailure(result: { exitCode: number | null; timedOut: boolean }): string | null {
  if (result.timedOut) return `timed out after ${OPENGREP_WARM_TIMEOUT_MS / 1000} s`;
  return result.exitCode === 0 ? null : `exited with code ${result.exitCode ?? 'null'}`;
}

/**
 * Plan 6B-6: unpacks OpenGrep's cache before an engine's scan, one `qualor scan` process at a time.
 * `OPENGREP_GROUP` keeps the two engines of one scan apart, but separate `qualor scan` processes
 * sharing one cold cache (parallel jobs on one CI runner) still crashed: 10 of 40 scans in a
 * fresh qualor/scanner container, four at a time. Each process holds the lock file
 * `.qualor-unpack.lock` in the cache root while its launcher runs `--version` (in the work
 * directory, never the checkout), so only one launcher ever unpacks; the scan that follows finds
 * the cache complete and writes nothing to it. Never fails: a failed launch is a warning, and the
 * scan's own launch reports what goes wrong there. `lock` is for tests.
 */
export async function warmOpengrep(
  ctx: AnalyzerContext,
  command: string,
  lock: FileLockOptions = {},
): Promise<void> {
  const dir = opengrepCacheDir(ctx.env);
  if (dir === null) return;
  const file = path.join(dir, '.qualor-unpack.lock');
  let failure: string | null;
  try {
    failure = await withFileLock(
      file,
      async () =>
        warmFailure(
          await ctx.exec(command, OPENGREP_WARM_ARGS, {
            cwd: ctx.workDir,
            env: deadProxyEnv(),
            dropEnv: isOpengrepVariable,
            timeoutMs: OPENGREP_WARM_TIMEOUT_MS,
          }),
        ),
      {
        ...lock,
        onWait: () => ctx.log.info(`waiting for another qualor scan to unpack OpenGrep (${file})`),
        onUnlocked: (why) => ctx.log.warn(`${WARM_FAILED} runs without the lock: ${why}`),
      },
    );
  } catch (err) {
    ctx.log.debug(`${command} ${OPENGREP_WARM_ARGS.join(' ')}: ${String(err)}`);
    failure = 'could not run';
  }
  if (failure !== null) ctx.log.warn(`${WARM_FAILED} ${failure}; the scans run anyway`);
}

/** A config path, `null` for a `qualor-default` that holds no rules, or why none can be used. */
type Resolved = string | null | { skip: string } | { missing: string } | { error: string };

const NO_DEFAULT_RULES =
  'the qualor/scanner image ships no Semgrep rules yet; set analyzers.semgrep.configs to local rule files';

/**
 * Whether the image's rule directory holds at least one rule file (`.yml`, `.yaml` or `.json`,
 * at any depth). The image ships the directory empty until that is decided, and the tools refuse
 * a config without rules, so an empty directory must mean "no default rules", not a failed run.
 */
function hasRuleFile(dir: string): boolean {
  const stack = [dir];
  let seen = 0;
  while (stack.length > 0 && seen < MAX_RULE_FILES) {
    const current = stack.pop() as string;
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      // The bound holds inside one directory too: a huge directory is not read to its end.
      if (seen >= MAX_RULE_FILES) return false;
      seen += 1;
      if (entry.isDirectory()) stack.push(path.join(current, entry.name));
      else if (RULE_FILE.test(entry.name)) return true;
    }
  }
  return false;
}

/**
 * One `configs` entry: `qualor-default` (the image's rule directory), or a rule file or directory
 * in the repository, passed to the tool as an absolute path, so no entry can ever be read as a
 * registry id, a saved snippet (`a:b`) or a URL. A URL (any scheme, `git+https:` included) and a
 * path outside the repository, as written or through a link, are configuration errors (the
 * offline guarantee, ruling V4); a missing file is `missing`, the entry as shown.
 */
function resolveConfig(root: string, entry: string, defaultRulesDir: string): Resolved {
  if (entry === 'qualor-default') {
    if (!existsSync(defaultRulesDir)) {
      return {
        skip: 'qualor-default rules come with the qualor/scanner image; set analyzers.semgrep.configs to local rule files',
      };
    }
    return hasRuleFile(defaultRulesDir) ? defaultRulesDir : null;
  }
  const name = `config ${shown(entry)}`;
  if (isUrl(entry)) return { error: `${name} is a URL (the tool would download it)` };
  const file = path.resolve(root, entry);
  if (!within(path.resolve(root), file)) return { error: `${name} is outside the repository` };
  try {
    lstatSync(file);
  } catch {
    if (!staysInside(root, file)) return { error: `${name} is outside the repository` };
    return { missing: shown(entry) };
  }
  if (!staysInside(root, file)) return { error: `${name} is outside the repository` };
  return file;
}

/**
 * The absolute paths `configs` resolves to. An entry that cannot be used does not drop the others:
 * a `qualor-default` without rules here is left out, and a file that does not exist is logged at
 * warn (`log`) and its path added to `missing` (the caller reports it). Only when nothing is left
 * is the reason a skip.
 */
export function resolveConfigs(
  root: string,
  configs: readonly string[],
  defaultRulesDir: string,
  log?: Logger,
  missing: string[] = [],
): string[] | { skip: string } | { error: string } {
  if (configs.length > MAX_SEMGREP_CONFIGS) {
    return { error: `more than ${MAX_SEMGREP_CONFIGS} configs` };
  }
  const out: string[] = [];
  const gone: string[] = [];
  let noDefault = NO_DEFAULT_RULES;
  for (const c of configs) {
    const r = resolveConfig(root, c, defaultRulesDir);
    if (r === null) continue;
    if (typeof r === 'string') out.push(r);
    else if ('missing' in r) gone.push(r.missing);
    else if ('error' in r) return r;
    else noDefault = r.skip;
  }
  for (const file of gone) log?.warn(`semgrep: ${file} does not exist`);
  missing.push(...gone);
  if (out.length > 0) return out;
  if (gone.length === 1) return { skip: `config ${gone[0]} does not exist` };
  if (gone.length > 1) return { skip: `configs ${gone.join(', ')} do not exist` };
  return { skip: noDefault };
}

const RULE_FILE = /\.(ya?ml|json)$/i;
const JSONNET_FILE = /\.(jsonnet|libsonnet)$/i;

/** The name, or for a link the name of its target, has a Jsonnet extension. */
const isJsonnet = (file: string): boolean =>
  JSONNET_FILE.test(file) || JSONNET_FILE.test(path.basename(real(file)));

/**
 * The rule files the tool would read from one repository config: the file itself (whatever its
 * name), or every `.yml`/`.yaml`/`.json` file below a directory, following links that stay inside
 * the repository. A link out of the repository, a Jsonnet file (by its name or its link target's),
 * a config or rule file that is not a regular file (a FIFO would hang the check and the tool), or
 * a tree too large to check completely is an error. Jsonnet is refused as a precaution: neither
 * Semgrep 1.178 nor OpenGrep 1.30 evaluates a `.jsonnet` config (both exit 7), but Semgrep's
 * Jsonnet support resolved `import` of registry packs and URLs, and a later version may again.
 */
function ruleFiles(root: string, top: string): { files: string[] } | { error: string } {
  const rel = (p: string) => shown(path.relative(root, p).split(path.sep).join('/'));
  const jsonnet = (p: string) => ({
    error: `rule file ${rel(p)} is Jsonnet (not supported: its import could name a registry pack or a URL)`,
  });
  const notRegular = (p: string) => ({ error: `rule file ${rel(p)} is not a regular file` });
  let topStat: Stats;
  try {
    topStat = statSync(top);
  } catch {
    return { files: [] };
  }
  if (!topStat.isDirectory()) {
    if (isJsonnet(top)) return jsonnet(top);
    return topStat.isFile() ? { files: [top] } : notRegular(top);
  }
  const files: string[] = [];
  const visited = new Set<string>([real(top)]);
  const stack = [top];
  let entries = 0;
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let handle;
    try {
      handle = opendirSync(current);
    } catch {
      continue;
    }
    try {
      for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
        entries += 1;
        if (entries > MAX_ENTRIES_CHECKED || files.length > MAX_RULE_FILES) {
          return { error: `config ${rel(top)} has too many files to check` };
        }
        const full = path.join(current, entry.name);
        let dir = entry.isDirectory();
        let file = entry.isFile();
        if (entry.isSymbolicLink()) {
          if (!staysInside(root, full)) {
            return { error: `rule file ${rel(full)} links outside the repository` };
          }
          try {
            const target = statSync(full);
            dir = target.isDirectory();
            file = target.isFile();
          } catch {
            continue;
          }
        }
        if (dir) {
          const key = real(full);
          if (!visited.has(key)) {
            visited.add(key);
            stack.push(full);
          }
        } else if (JSONNET_FILE.test(entry.name) || (file && isJsonnet(full))) {
          return jsonnet(full);
        } else if (RULE_FILE.test(entry.name)) {
          if (!file) return notRegular(full);
          files.push(full);
        }
      }
    } finally {
      handle.closeSync();
    }
  }
  return { files: files.sort() };
}

/** A JSON object (not null, not an array); the qualor engine reads SARIF with it too. */
export const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * A join-mode rule (`mode: join`) runs the rules its `join.refs[].rule` name, and both tools
 * resolve those like `--config`: a registry id or a URL is fetched (verified with Semgrep 1.178.0
 * and OpenGrep 1.30.0 against a local listener). Such a rule is refused, whatever its refs say.
 * The file is read as YAML (JSON is YAML too) with merge keys applied; anything that cannot be
 * checked with certainty (not UTF-8, a syntax error, a duplicate key, an alias bomb) is an error.
 */
function checkRuleFile(root: string, file: string): string | null {
  const name = `rule file ${shown(path.relative(root, file).split(path.sep).join('/'))}`;
  let bytes: Buffer;
  try {
    if (statSync(file).size > MAX_RULE_FILE_BYTES) {
      return `${name} is larger than ${MAX_RULE_FILE_BYTES / 1024 / 1024} MiB`;
    }
    bytes = readFileSync(file);
  } catch {
    return `${name} cannot be read`;
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return `${name} is not UTF-8`;
  }
  try {
    for (const doc of parseAllDocuments(text, { merge: true, uniqueKeys: true })) {
      if (doc.errors.length > 0) return `${name} cannot be parsed as YAML`;
      const value: unknown = doc.toJS({ maxAliasCount: MAX_ALIAS_COUNT });
      if (!isObject(value) || !Array.isArray(value['rules'])) continue;
      for (const rule of value['rules'] as unknown[]) {
        if (!isObject(rule)) continue;
        if (rule['mode'] === 'join' || Object.hasOwn(rule, 'join')) {
          const id = typeof rule['id'] === 'string' ? rule['id'] : '(no id)';
          return `${name}: rule ${shown(id)} is a join rule, which can load rules from a URL or the registry (not supported)`;
        }
      }
    }
  } catch {
    return `${name} cannot be parsed as YAML`;
  }
  return null;
}

/**
 * The Semgrep/OpenGrep configuration errors of config.md §6 (exit 2): a config that is a URL, lies
 * outside the repository, or holds a rule file that could make the tool fetch rules (a join rule,
 * Jsonnet) or that cannot be checked. `qualor-default` (the image's own rules) is not checked; a
 * missing config is a skip reason, not an error.
 */
export function checkSemgrepConfig(root: string, config: QualorConfig): string | null {
  const configs = config.analyzers.semgrep.configs;
  if (configs.length > MAX_SEMGREP_CONFIGS) return `more than ${MAX_SEMGREP_CONFIGS} configs`;
  for (const entry of configs) {
    if (entry === 'qualor-default') continue;
    const r = resolveConfig(root, entry, DEFAULT_SEMGREP_RULES_DIR);
    if (typeof r !== 'string') {
      if (r !== null && 'error' in r) return r.error;
      continue;
    }
    const found = ruleFiles(root, r);
    if ('error' in found) return found.error;
    for (const file of found.files) {
      const problem = checkRuleFile(root, file);
      if (problem !== null) return problem;
    }
  }
  return null;
}

function findBinary(ctx: AnalyzerContext): { command: string; flavour: Flavour } | null {
  const wanted = ctx.config.analyzers.semgrep.binary;
  const order: Flavour[] = wanted === 'auto' ? ['opengrep', 'semgrep'] : [wanted];
  for (const flavour of order) {
    const command = ctx.resolveBinary(flavour);
    if (command !== null) return { command, flavour };
  }
  return null;
}

/** The most bytes of the project's own patterns passed to OpenGrep (the whole line stays far below Windows' 32,767). */
export const MAX_USER_EXCLUDE_BYTES = 8192;

/**
 * `--exclude` arguments for a scan that selects the files itself (below `.`): the built-in excludes
 * and the project's `sources.exclude` patterns that start with `**` + `/`. OpenGrep matches every
 * pattern at any depth (a leading `/` does not anchor it), while Qualor's scope matches from the
 * root, so any other pattern (`gen/**`) would also drop `a/gen/**`, which Qualor scans. The findings
 * on the files left out are dropped afterwards anyway. The project part is capped at 8 kB so the
 * command line stays short; what was left out is logged at debug.
 */
export function excludeFlags(config: QualorConfig, log?: Logger): string[] {
  const user: string[] = [];
  let bytes = 0;
  let left = 0;
  for (const g of config.sources.exclude) {
    const size = Buffer.byteLength(g) + 1;
    if (!g.startsWith('**/') || bytes + size > MAX_USER_EXCLUDE_BYTES) {
      left += 1;
      continue;
    }
    bytes += size;
    user.push(g);
  }
  if (left > 0) {
    log?.debug(
      `${left} sources.exclude pattern(s) not passed to OpenGrep (only patterns starting with **/ that fit 8 kB are); their findings are dropped after the scan`,
    );
  }
  return [...BUILTIN_EXCLUDES, ...user].flatMap((g) => ['--exclude', g]);
}

export function createSemgrepAnalyzer(defaultRulesDir = DEFAULT_SEMGREP_RULES_DIR): Analyzer {
  const prepare = async (ctx: AnalyzerContext): Promise<Preparation> => {
    // `qualor scan` stops with exit 2 on these before any analyzer runs (checkConfig); this is
    // the same check for any other caller of the runner.
    const problem = checkSemgrepConfig(ctx.root, ctx.config);
    if (problem !== null) return { skip: problem };
    const missing: string[] = [];
    const configs = resolveConfigs(
      ctx.root,
      ctx.config.analyzers.semgrep.configs,
      defaultRulesDir,
      ctx.log,
      missing,
    );
    // One report warning per file the configuration names that does not exist.
    const warnings: NormalizeWarning[] = missing.map((file) => ({
      code: 'SEMGREP_CONFIG_MISSING',
      message: `${file} does not exist`,
      count: 1,
    }));
    if (!Array.isArray(configs)) {
      if ('error' in configs) return { skip: configs.error };
      return warnings.length > 0 ? { skip: configs.skip, warnings } : configs;
    }
    const binary = findBinary(ctx);
    if (binary === null) {
      const wanted = ctx.config.analyzers.semgrep.binary;
      return {
        unavailable: `${wanted === 'auto' ? 'OpenGrep or Semgrep' : wanted} is not installed`,
      };
    }
    if (binary.flavour === 'opengrep') await warmOpengrep(ctx, binary.command);
    const out = path.join(ctx.workDir, 'semgrep.sarif');
    return {
      run: {
        command: binary.command,
        args: [
          'scan',
          ...configs.flatMap((c) => ['--config', c]),
          '--sarif',
          '--output',
          out,
          ...offlineFlags(binary.flavour),
          // Below `.` the tool skips files over 1,000,000 bytes silently; scan up to the CLI's limit.
          '--max-target-bytes',
          String(MAX_ANALYZED_BYTES),
          ...excludeFlags(ctx.config, ctx.log),
          '.',
        ],
        cwd: ctx.root,
        env: deadProxyEnv(),
        dropEnv: isOpengrepVariable,
        sarifPath: out,
        ...(binary.flavour === 'opengrep' && { exclusive: OPENGREP_GROUP }),
        // Without --error both exit 0 with findings; anything else is a failure.
        okExitCodes: [0],
        version: null,
        ...(warnings.length > 0 && { warnings }),
      },
    };
  };
  // Languages: [] — rules can target any language (and config files), so it always runs under auto.
  return { id: 'semgrep', languages: [], prepare, checkConfig: checkSemgrepConfig };
}

export const semgrepAnalyzer = createSemgrepAnalyzer();
