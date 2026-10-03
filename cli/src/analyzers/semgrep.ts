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
import { isUrl, type QualorConfig } from '@qualor/shared';
import { parseAllDocuments } from 'yaml';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { real, staysInside, within } from './binary';
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

/** A config path, `null` for a `qualor-default` that holds no rules, or why none can be used. */
type Resolved = string | null | { skip: string } | { error: string };

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
 * offline guarantee, ruling V4); a missing file is a skip reason.
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
    return { skip: `${name} does not exist` };
  }
  if (!staysInside(root, file)) return { error: `${name} is outside the repository` };
  return file;
}

export function resolveConfigs(
  root: string,
  configs: readonly string[],
  defaultRulesDir: string,
): string[] | { skip: string } | { error: string } {
  if (configs.length > MAX_SEMGREP_CONFIGS) {
    return { error: `more than ${MAX_SEMGREP_CONFIGS} configs` };
  }
  const out: string[] = [];
  for (const c of configs) {
    const r = resolveConfig(root, c, defaultRulesDir);
    if (r === null) continue;
    if (typeof r !== 'string') return r;
    out.push(r);
  }
  if (out.length === 0) return { skip: NO_DEFAULT_RULES };
  return out;
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

export function createSemgrepAnalyzer(defaultRulesDir = DEFAULT_SEMGREP_RULES_DIR): Analyzer {
  const prepare = (ctx: AnalyzerContext): Promise<Preparation> => {
    // `qualor scan` stops with exit 2 on these before any analyzer runs (checkConfig); this is
    // the same check for any other caller of the runner.
    const problem = checkSemgrepConfig(ctx.root, ctx.config);
    if (problem !== null) return Promise.resolve({ skip: problem });
    const configs = resolveConfigs(ctx.root, ctx.config.analyzers.semgrep.configs, defaultRulesDir);
    if (!Array.isArray(configs)) {
      return Promise.resolve('skip' in configs ? configs : { skip: configs.error });
    }
    const binary = findBinary(ctx);
    if (binary === null) {
      const wanted = ctx.config.analyzers.semgrep.binary;
      return Promise.resolve({
        unavailable: `${wanted === 'auto' ? 'OpenGrep or Semgrep' : wanted} is not installed`,
      });
    }
    const out = path.join(ctx.workDir, 'semgrep.sarif');
    return Promise.resolve({
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
          '.',
        ],
        cwd: ctx.root,
        env: deadProxyEnv(),
        dropEnv: isOpengrepVariable,
        sarifPath: out,
        // Without --error both exit 0 with findings; anything else is a failure.
        okExitCodes: [0],
        version: null,
      },
    });
  };
  // Languages: [] — rules can target any language (and config files), so it always runs under auto.
  return { id: 'semgrep', languages: [], prepare, checkConfig: checkSemgrepConfig };
}

export const semgrepAnalyzer = createSemgrepAnalyzer();
