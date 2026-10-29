import { createHash } from 'node:crypto';
import { existsSync, lstatSync, opendirSync, readFileSync, type Dir, type Stats } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  QUALOR_KIND_PROPERTY,
  QUALOR_SEVERITY_PROPERTY,
  qualorManifestSchema,
  qualorRuleHelpUri,
  qualorRuleId,
  type Language,
  type NormalizeWarning,
  type QualorManifest,
  type SarifLog,
} from '@qualor/shared';
import { MAX_ANALYZED_BYTES, type ScopeFile } from '../discovery/discover';
import { isInside } from './binary';
import { deadProxyEnv } from './offline';
import { shown } from './reason';
import {
  isObject,
  isOpengrepVariable,
  MAX_RULE_FILE_BYTES,
  offlineFlags,
  OPENGREP_GROUP,
  excludeFlags,
  warmOpengrep,
} from './semgrep';
import type {
  Analyzer,
  AnalyzerContext,
  Preparation,
  TaintFallbackReason,
  TaintRun,
} from './types';

/** Where the qualor/scanner image installs Qualor's security rules (install-qualor-rules.sh). */
export const DEFAULT_QUALOR_RULES_DIR = '/opt/qualor/rules/qualor';

/** The languages of the pack's rules: `js` covers JavaScript and TypeScript. */
export const QUALOR_LANGUAGES: readonly Language[] = [
  'javascript',
  'typescript',
  'python',
  'java',
  'go',
  'csharp',
];

export const QUALOR_RULES_NOT_INSTALLED =
  "Qualor's security rules are not installed (set QUALOR_RULES_DIR to a rules release, or use a qualor/scanner image that includes them)";

/**
 * The longest file list passed on OpenGrep's command line: Linux allows about 2 MiB for the
 * arguments and the environment together, Windows 32,767 characters for the whole command line.
 * Above it, OpenGrep selects the files itself (config.md §6).
 */
export const MAX_TARGET_ARG_BYTES = process.platform === 'win32' ? 24_000 : 1_000_000;

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_PACK_ENTRIES = 100_000;

export interface QualorPack {
  dir: string;
  manifest: QualorManifest;
}

interface PackWalk {
  stack: string[];
  files: string[];
  entries: number;
}

/**
 * Reads the pack directory `rel` into `walk`: subdirectories onto its stack, anything else into its
 * files. Returns why the pack is refused, or null.
 */
function walkPackDir(dir: string, rel: string, walk: PackWalk): string | null {
  let handle: Dir;
  try {
    handle = opendirSync(path.join(dir, ...rel.split('/')));
  } catch {
    return 'the rules pack cannot be read';
  }
  try {
    for (let e = handle.readSync(); e !== null; e = handle.readSync()) {
      walk.entries += 1;
      if (walk.entries > MAX_PACK_ENTRIES) return 'the rules pack has too many files';
      const child = `${rel}/${e.name}`;
      if (e.isSymbolicLink()) return `the rules pack holds a symbolic link (${shown(child)})`;
      if (e.isDirectory()) walk.stack.push(child);
      else walk.files.push(child);
    }
  } finally {
    handle.closeSync();
  }
  return null;
}

/**
 * Every entry below `<dir>/rules` that is not a directory, as `rules/…` paths, whatever its name:
 * OpenGrep reads any config it is given (a `.jsonnet` file too), so the manifest must list each one.
 * Any symbolic link is a problem.
 */
function packFiles(dir: string): { files: string[] } | { problem: string } {
  let top: Stats;
  try {
    top = lstatSync(path.join(dir, 'rules'));
  } catch {
    return { problem: 'the rules pack has no rules/ directory' };
  }
  if (!top.isDirectory()) return { problem: 'the rules pack has no rules/ directory' };
  const walk: PackWalk = { stack: ['rules'], files: [], entries: 0 };
  while (walk.stack.length > 0) {
    const problem = walkPackDir(dir, walk.stack.pop() as string, walk);
    if (problem !== null) return { problem };
  }
  return { files: walk.files.sort() };
}

/**
 * config.md §6: the pack at `dir` when `rules/` holds exactly the files `manifest.json` lists, each
 * a regular file whose SHA-256 matches; else why not, as a fixed reason for the report.
 */
export function loadQualorPack(dir: string): QualorPack | { problem: string } {
  const manifestFile = path.join(dir, 'manifest.json');
  let stat: Stats;
  try {
    stat = lstatSync(manifestFile);
  } catch {
    return { problem: 'the rules pack has no manifest.json' };
  }
  if (!stat.isFile()) return { problem: 'the rules pack manifest.json is not a regular file' };
  if (stat.size > MAX_MANIFEST_BYTES) {
    return { problem: 'the rules pack manifest.json is larger than 1 MiB' };
  }
  let manifest: QualorManifest;
  try {
    manifest = qualorManifestSchema.parse(JSON.parse(readFileSync(manifestFile, 'utf8')));
  } catch {
    return { problem: 'the rules pack manifest.json is not valid' };
  }
  const found = packFiles(dir);
  if ('problem' in found) return found;
  const listed = new Map(manifest.rules.map((r) => [r.path, r.sha256]));
  for (const file of found.files) {
    if (!listed.has(file)) {
      return { problem: `the rules pack holds ${shown(file)}, which its manifest does not list` };
    }
  }
  for (const [file, sha256] of listed) {
    const full = path.join(dir, ...file.split('/'));
    let s: Stats;
    try {
      s = lstatSync(full);
    } catch {
      return { problem: `the rules pack is missing ${file}` };
    }
    if (!s.isFile() || s.size > MAX_RULE_FILE_BYTES) {
      return { problem: `the rules pack file ${file} is not a regular rule file` };
    }
    if (createHash('sha256').update(readFileSync(full)).digest('hex') !== sha256) {
      return { problem: `the rules pack file ${file} does not match its manifest checksum` };
    }
  }
  return { dir, manifest };
}

/** The engine version a SARIF driver names: its semantic version, else its version, else OpenGrep. */
function engineVersion(driver: Record<string, unknown>): string {
  if (typeof driver['semanticVersion'] === 'string') return driver['semanticVersion'];
  if (typeof driver['version'] === 'string') return driver['version'];
  return 'OpenGrep';
}

/** One OpenGrep rule descriptor made Qualor's (see withQualorRules). */
function qualorRule(rule: unknown, byId: Map<string, QualorManifest['rules'][number]>): void {
  if (!isObject(rule) || typeof rule['id'] !== 'string') return;
  const id = qualorRuleId(rule['id']);
  if (id === null) return;
  rule['id'] = id;
  rule['name'] = id;
  // Each rule's page in the qualor-rules repository, in place of whatever OpenGrep wrote.
  const helpUri = qualorRuleHelpUri(id);
  if (helpUri !== null) rule['helpUri'] = helpUri;
  else delete rule['helpUri'];
  const entry = byId.get(id);
  if (entry === undefined) return;
  rule['shortDescription'] = { text: entry.title };
  rule['properties'] = {
    ...(isObject(rule['properties']) ? rule['properties'] : {}),
    [QUALOR_KIND_PROPERTY]: entry.kind,
    [QUALOR_SEVERITY_PROPERTY]: entry.severity,
  };
}

/**
 * One OpenGrep result made Qualor's: its rule id mapped, its in-source suppressions removed. Only
 * the taint engine's results (`engine`) keep a `confidence` property (6B-C# engine spec R-9): an
 * OpenGrep that copied its rules' metadata (`confidence: high|medium`) into its results would
 * otherwise mark its findings "possible" (fix round 1 of Task 28, M4).
 */
function qualorResult(result: unknown, engine: boolean): void {
  if (!isObject(result)) return;
  const properties = result['properties'];
  if (!engine && isObject(properties) && 'confidence' in properties) {
    const rest = Object.fromEntries(Object.entries(properties).filter(([k]) => k !== 'confidence'));
    if (Object.keys(rest).length > 0) result['properties'] = rest;
    else delete result['properties'];
  }
  if (typeof result['ruleId'] === 'string') {
    result['ruleId'] = qualorRuleId(result['ruleId']) ?? result['ruleId'];
  }
  const suppressions = result['suppressions'];
  if (!Array.isArray(suppressions)) return;
  const kept = suppressions.filter((s) => !(isObject(s) && s['kind'] === 'inSource'));
  if (kept.length > 0) result['suppressions'] = kept;
  else delete result['suppressions'];
}

/** One OpenGrep driver made Qualor's: its version names the pack, its rules are mapped. */
function qualorDriver(
  driver: Record<string, unknown>,
  manifest: QualorManifest,
  byId: Map<string, QualorManifest['rules'][number]>,
): void {
  driver['version'] = `${engineVersion(driver)} + qualor-rules ${manifest.version}`;
  for (const rule of Array.isArray(driver['rules']) ? driver['rules'] : []) qualorRule(rule, byId);
}

/**
 * config.md §6: OpenGrep's SARIF made Qualor's. Rule ids `<lang>.<name>` become `<lang>/<name>`;
 * each gets its page in the qualor-rules repository as its help link; a rule the manifest lists gets
 * its title as the short description and its kind and severity as properties (report-format.md
 * §7.1); in-source suppressions (`nosem` comments in the checkout) are
 * removed; the driver version names the pack; a result keeps a `confidence` property only when
 * `engine` (the taint engine's SARIF). Mutates `output` in place; anything that is not a SARIF log
 * is left as it is.
 */
export function withQualorRules(
  output: unknown,
  manifest: QualorManifest,
  o: { engine?: boolean } = {},
): void {
  if (!isObject(output) || !Array.isArray(output['runs'])) return;
  const byId = new Map(manifest.rules.map((r) => [r.id, r]));
  for (const run of output['runs']) {
    if (!isObject(run)) continue;
    const tool = run['tool'];
    const driver = isObject(tool) ? tool['driver'] : undefined;
    if (isObject(driver)) qualorDriver(driver, manifest, byId);
    for (const result of Array.isArray(run['results']) ? run['results'] : []) {
      qualorResult(result, o.engine === true);
    }
  }
}

/** The OpenGrep version a SARIF log names, or null. */
function opengrepVersion(output: unknown): string | null {
  if (!isObject(output) || !Array.isArray(output['runs'])) return null;
  const run: unknown = output['runs'][0];
  const tool = isObject(run) ? run['tool'] : undefined;
  const driver = isObject(tool) ? tool['driver'] : undefined;
  return isObject(driver) && typeof driver['semanticVersion'] === 'string'
    ? driver['semanticVersion']
    : null;
}

/**
 * config.md §6: the pack in QUALOR_RULES_DIR, else the image's, checked against its manifest; or
 * why the qualor engine skips (the image's pack is not there) or cannot run. `env` is the
 * analyzer's (or, in `qualor dotnet end`, the CLI's) environment.
 */
export function locateQualorPack(
  root: string,
  env: Readonly<Record<string, string | undefined>>,
  defaultDir: string = DEFAULT_QUALOR_RULES_DIR,
): QualorPack | { skip: string } | { unavailable: string } {
  const fromEnv = env['QUALOR_RULES_DIR'];
  const dir = fromEnv || defaultDir;
  if (!path.isAbsolute(dir) || isInside(root, dir)) {
    return { unavailable: 'QUALOR_RULES_DIR must be an absolute path outside the repository' };
  }
  // Ruling G6: the image's pack missing on a plain host is a skip; a named directory that does
  // not exist is a configuration problem.
  if (!existsSync(dir)) {
    return fromEnv
      ? { unavailable: 'QUALOR_RULES_DIR does not exist' }
      : { skip: QUALOR_RULES_NOT_INSTALLED };
  }
  const pack = loadQualorPack(dir);
  return 'problem' in pack ? { unavailable: pack.problem } : pack;
}

/** The report warning of R-4 when the taint engine did not replace the OpenGrep C# rules. */
export const TAINT_ENGINE_FALLBACK = 'TAINT_ENGINE_FALLBACK';

/**
 * Fixed texts per reason: the engine's own output (its stderr, the files it names) goes to the
 * log only, never into the report (config.md §6).
 */
const FALLBACK_TEXT: Record<TaintFallbackReason, string> = {
  'no-engine': 'the rules pack has no Roslyn taint engine',
  'engine-mismatch': 'its files do not match the rules pack manifest',
  'no-inputs': 'the build recorded no compiler inputs',
  budget: 'the analysis did not complete within its time or memory budget',
  crash: 'the engine failed',
  'dotnet-missing': 'dotnet is not installed',
  load: 'the sources of a project could not be loaded',
};

/** The report warning of R-E42: projects the engine analysed with load or compile errors. */
export const TAINT_ENGINE_PROJECT_ERRORS = 'TAINT_ENGINE_PROJECT_ERRORS';

function taintProblemWarning(taint: TaintRun | null): NormalizeWarning[] {
  if (taint?.kind !== 'ok' || taint.problems === undefined) return [];
  const { projects, unresolvedReferences } = taint.problems;
  const refs = unresolvedReferences > 0 ? ` (${unresolvedReferences} unresolved reference(s))` : '';
  return [
    {
      code: TAINT_ENGINE_PROJECT_ERRORS,
      message: `Qualor's Roslyn taint engine analysed ${projects} project(s) with load or compile errors${refs}; their findings may be incomplete`,
      count: projects,
    },
  ];
}

/** R-4: the report warning naming why the OpenGrep C# rules ran in the engine's place. */
export function taintFallbackWarning(
  reason: TaintFallbackReason,
  manifest?: QualorManifest,
  opengrepMissing = false,
): NormalizeWarning {
  // A pack without C# rules (before 2026.10.5) leaves nothing to analyse the C# files.
  const csharpRules =
    manifest === undefined || manifest.rules.some((r) => r.id.startsWith('csharp/'));
  const then = fallbackOutcome(csharpRules, opengrepMissing);
  return {
    code: TAINT_ENGINE_FALLBACK,
    message: `Qualor's Roslyn taint engine did not run (${reason}: ${FALLBACK_TEXT[reason]}); ${then}`,
    count: 1,
  };
}

/** What analysed the C# files in the engine's place, for `taintFallbackWarning`. */
function fallbackOutcome(csharpRules: boolean, opengrepMissing: boolean): string {
  if (!csharpRules) {
    return "the rules pack has no OpenGrep C# rules, so Qualor's C# security rules did not run";
  }
  if (opengrepMissing)
    return "OpenGrep is not installed, so Qualor's C# security rules did not run";
  return 'the OpenGrep C# rules analysed the C# files';
}

/** `value` when it is an array, else an empty one (an absent or malformed SARIF property). */
function arrayOf(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** The array property `key` of a SARIF object, or an empty one. */
function arrayProperty(o: unknown, key: string): unknown[] {
  return isObject(o) ? arrayOf(o[key]) : [];
}

/** Two SARIF locations on the same file and line. */
function sameLine(a: unknown, b: unknown): boolean {
  const key = (l: unknown) => {
    const physical = isObject(l) ? l['physicalLocation'] : undefined;
    const artifact = isObject(physical) ? physical['artifactLocation'] : undefined;
    const region = isObject(physical) ? physical['region'] : undefined;
    return JSON.stringify([
      isObject(artifact) ? artifact['uri'] : null,
      isObject(artifact) ? artifact['uriBaseId'] : null,
      isObject(region) ? region['startLine'] : null,
    ]);
  };
  return key(a) === key(b);
}

/**
 * Spec §4.2: the engine's path from source to sink (`codeFlows[].threadFlows[].locations[]
 * .location`, SARIF §3.38) becomes the result's related locations, ahead of the other sources it
 * already lists there; the step on the sink's own line is the primary location already.
 */
function flowAsRelated(result: Record<string, unknown>): void {
  const primary: unknown = arrayOf(result['locations'])[0];
  const steps = arrayOf(result['codeFlows'])
    .flatMap(flowLocations)
    .filter((location) => !sameLine(location, primary));
  if (steps.length === 0) return;
  result['relatedLocations'] = [...steps, ...arrayOf(result['relatedLocations'])];
}

/** The locations of a code flow's steps (`threadFlows[].locations[].location`), in order. */
function flowLocations(flow: unknown): Record<string, unknown>[] {
  const locations: Record<string, unknown>[] = [];
  for (const thread of arrayProperty(flow, 'threadFlows')) {
    for (const step of arrayProperty(thread, 'locations')) {
      const location = isObject(step) ? step['location'] : undefined;
      if (isObject(location)) locations.push(location);
    }
  }
  return locations;
}

/** The taint engine's SARIF made Qualor's, and the engine version it names. */
interface TaintEngineLog {
  sarif: Record<string, unknown>;
  version: string;
}

/**
 * 6B-C# R: the taint engine's SARIF made Qualor's, as OpenGrep's is (`withQualorRules`: ids
 * `csharp/<name>`, title, kind and severity from the manifest), with the manifest's CWE as the
 * rules' tags, the flows as related locations and a version naming the engine and the pack.
 * Works on a copy: `qualor dotnet end`'s run stays as it was.
 */
function taintEngineLog(
  log: SarifLog,
  manifest: QualorManifest,
  root: string,
  tests: ReadonlySet<string>,
): TaintEngineLog {
  const sarif = structuredClone(log) as Record<string, unknown>;
  dropResultsOn(sarif, tests, root);
  withQualorRules(sarif, manifest, { engine: true });
  const byId = new Map(manifest.rules.map((r) => [r.id, r]));
  const declared = manifest.dotnetEngine;
  const engineVersion =
    declared !== undefined && !('invalid' in declared) ? declared.version : 'unknown';
  const version = `qualor-taint ${engineVersion} + qualor-rules ${manifest.version}`;
  for (const run of arrayOf(sarif['runs'])) {
    if (!isObject(run)) continue;
    const tool = run['tool'];
    const driver = isObject(tool) ? tool['driver'] : undefined;
    if (isObject(driver)) withEngineDriver(driver, version, byId);
    for (const result of arrayOf(run['results'])) {
      if (isObject(result)) flowAsRelated(result);
    }
  }
  return { sarif, version };
}

/** The engine run's driver: the version naming engine and pack, the manifest's CWE as tags. */
function withEngineDriver(
  driver: Record<string, unknown>,
  version: string,
  byId: ReadonlyMap<string, QualorManifest['rules'][number]>,
): void {
  driver['version'] = version;
  for (const rule of arrayOf(driver['rules'])) {
    if (!isObject(rule) || typeof rule['id'] !== 'string') continue;
    const entry = byId.get(rule['id']);
    const properties = isObject(rule['properties']) ? rule['properties'] : {};
    // The CWE as OpenGrep's rules carry it (their tags), for the report's `cwe`.
    if (entry !== undefined && !Array.isArray(properties['tags'])) {
      rule['properties'] = { ...properties, tags: [...entry.cwe, 'security'] };
    }
  }
}

/** A repository path as compared with the engine's files: case-insensitive on Windows. */
function pathKey(rel: string): string {
  return process.platform === 'win32' ? rel.toLowerCase() : rel;
}

/** The repository path of an OpenGrep result's first location, or null. */
function resultPath(result: Record<string, unknown>, root: string): string | null {
  const locations = result['locations'];
  const first: unknown = Array.isArray(locations) ? locations[0] : undefined;
  const physical = isObject(first) ? first['physicalLocation'] : undefined;
  const artifact = isObject(physical) ? physical['artifactLocation'] : undefined;
  const uri = isObject(artifact) ? artifact['uri'] : undefined;
  if (typeof uri !== 'string') return null;
  try {
    const rel = uri.startsWith('file:')
      ? path.relative(root, fileURLToPath(uri)).split(path.sep).join('/')
      : decodeURIComponent(uri).replace(/^(\.\/)+/, '');
    return rel;
  } catch {
    return null;
  }
}

/** Removes the results whose first location is a file in `tests` (keys as `pathKey`). */
function dropResultsOn(output: unknown, tests: ReadonlySet<string>, root: string): void {
  if (tests.size === 0 || !isObject(output) || !Array.isArray(output['runs'])) return;
  for (const run of output['runs']) {
    if (!isObject(run) || !Array.isArray(run['results'])) continue;
    run['results'] = run['results'].filter((r) => {
      const rel = isObject(r) ? resultPath(r, root) : null;
      return rel === null || !tests.has(pathKey(rel));
    });
  }
}

/**
 * R-4 in a scan with other files too: OpenGrep's C# results on the files the engine analysed are
 * dropped (OpenGrep selects the files itself when they do not fit one command line, those among
 * them) and the engine's runs follow OpenGrep's, so the engine version stays OpenGrep's with the
 * pack.
 */
function withTaintEngineRuns(
  output: unknown,
  engine: Record<string, unknown>,
  root: string,
  byEngine: (rel: string) => boolean,
): void {
  if (!isObject(output) || !Array.isArray(output['runs'])) return;
  for (const run of output['runs']) {
    if (!isObject(run) || !Array.isArray(run['results'])) continue;
    run['results'] = run['results'].filter((r) => {
      if (!isObject(r) || typeof r['ruleId'] !== 'string' || !r['ruleId'].startsWith('csharp/')) {
        return true;
      }
      const rel = resultPath(r, root);
      return rel === null || !byEngine(rel);
    });
  }
  const runs: unknown[] = Array.isArray(engine['runs']) ? engine['runs'] : [];
  output['runs'].push(...runs);
}

/** The engine's run alone, when it analysed every file in scope. */
function engineOnly(engine: TaintEngineLog, taint: TaintRun | null): Preparation {
  const warned = taintProblemWarning(taint);
  return { collected: { ...engine, ...(warned.length > 0 && { warnings: warned }) } };
}

/**
 * Whether the named files fit one OpenGrep command line of `budget` bytes, warning when they do
 * not. Each argument costs its bytes, the terminating NUL and a pointer in argv (8 bytes).
 */
function fitsCommandLine(files: readonly string[], budget: number, ctx: AnalyzerContext): boolean {
  const fits = files.reduce((n, f) => n + Buffer.byteLength(f) + 1 + 8, 0) <= budget;
  if (!fits) {
    ctx.log.warn(
      `qualor: ${files.length} files do not fit one command line; OpenGrep selects the files itself and findings outside the scan's scope are dropped`,
    );
  }
  return fits;
}

/** The taint engine's report warnings: its projects with errors, and why it did not run. */
function taintWarnings(
  taint: TaintRun | null,
  manifest: QualorManifest,
  opengrepMissing: boolean,
): NormalizeWarning[] {
  const warnings = taintProblemWarning(taint);
  if (taint?.kind === 'fallback') {
    warnings.push(taintFallbackWarning(taint.reason, manifest, opengrepMissing));
  }
  return warnings;
}

/** OpenGrep's targets: the named files, or `.` with the scan's excludes when they do not fit. */
function opengrepTargets(
  explicit: boolean,
  files: readonly string[],
  ctx: AnalyzerContext,
): string[] {
  if (explicit) return ['--', ...files];
  return [
    // OpenGrep parses vendored and minified bundles very slowly: tell it what a scan never
    // analyses (their findings are dropped afterwards anyway).
    ...excludeFlags(ctx.config, ctx.log),
    // Below `.` the tool skips files over 1,000,000 bytes silently; named files are always
    // scanned.
    '--max-target-bytes',
    String(MAX_ANALYZED_BYTES),
    '--x-ignore-semgrepignore-files',
    '.',
  ];
}

/** Warns when OpenGrep is not the version the rules pack is tested with. */
function warnOtherOpengrep(output: unknown, manifest: QualorManifest, ctx: AnalyzerContext): void {
  const ranWith = opengrepVersion(output);
  if (ranWith !== null && ranWith !== manifest.opengrep) {
    ctx.log.warn(
      `qualor: the rules pack ${manifest.version} is tested with OpenGrep ${manifest.opengrep}, not ${ranWith}`,
    );
  }
}

export function createQualorAnalyzer(
  o: { defaultDir?: string; maxTargetArgBytes?: number } = {},
): Analyzer {
  const defaultDir = o.defaultDir ?? DEFAULT_QUALOR_RULES_DIR;
  const budget = o.maxTargetArgBytes ?? MAX_TARGET_ARG_BYTES;
  const prepare = (ctx: AnalyzerContext): Preparation => {
    const pack = locateQualorPack(ctx.root, ctx.env, defaultDir);
    if (!('manifest' in pack)) return pack;
    const ofLanguages = ctx.files.filter((f) => QUALOR_LANGUAGES.includes(f.language));
    if (ofLanguages.length === 0) {
      return { skip: 'no JavaScript, TypeScript, Python, Java, Go or C# files in scope' };
    }
    // The rules analyse application code: test files (`tests.include`) are not targets.
    const inScope = ofLanguages.filter((f) => f.kind === 'main');
    if (inScope.length === 0) return { skip: 'skipped (no main files in scope)' };
    const relOf = (f: ScopeFile) => path.relative(ctx.root, f.absPath).split(path.sep).join('/');
    const tests = new Set(
      ofLanguages.filter((f) => f.kind === 'test').map((f) => pathKey(relOf(f))),
    );
    // R-4: the taint engine's complete run replaces the OpenGrep C# rules for the .cs files.
    const taint = ctx.dotnet?.kind === 'collected' ? ctx.dotnet.taint : null;
    const engine =
      taint?.kind === 'ok' ? taintEngineLog(taint.sarif, pack.manifest, ctx.root, tests) : null;
    // Only the files the engine analysed (those of a compilation the build recorded) leave
    // OpenGrep: a .cs file of no built project keeps the OpenGrep C# rules (fix round 1, I2).
    const analysed = new Set(taint?.kind === 'ok' ? taint.sources.map(pathKey) : []);
    const byEngine = (rel: string) => analysed.has(pathKey(rel));
    const files = inScope
      .map((f) => ({ f, rel: relOf(f) }))
      .filter(({ f, rel }) => engine === null || f.language !== 'csharp' || !byEngine(rel))
      .map(({ rel }) => rel);
    if (engine !== null && files.length === 0) return engineOnly(engine, taint);
    // Plan 6B-1: only the OpenGrep the pack is tested with, never Semgrep.
    const opengrep = ctx.resolveBinary('opengrep');
    // The engine's findings stand without OpenGrep (Task 24), whatever happens to its run.
    const salvage = engine === null ? undefined : { sarif: engine.sarif, version: engine.version };
    const fallbackWarnings = taintWarnings(taint, pack.manifest, opengrep === null);
    if (opengrep === null) {
      return {
        unavailable: 'OpenGrep is not installed',
        ...(salvage && { salvage }),
        ...(fallbackWarnings.length > 0 && { warnings: fallbackWarnings }),
      };
    }
    // Named files are scanned whatever .gitignore, .semgrepignore or OpenGrep's own ignores say.
    const explicit = fitsCommandLine(files, budget, ctx);
    const out = path.join(ctx.workDir, 'qualor.sarif');
    return {
      run: {
        command: opengrep,
        args: [
          'scan',
          '--config',
          path.join(pack.dir, 'rules'),
          // Taint followed through the file's own functions, as the pack is tested (plan 6B-6).
          ...(pack.manifest.taintIntrafile === true ? ['--taint-intrafile'] : []),
          '--sarif',
          '--output',
          out,
          ...offlineFlags('opengrep'),
          ...opengrepTargets(explicit, files, ctx),
        ],
        cwd: ctx.root,
        env: deadProxyEnv(),
        dropEnv: isOpengrepVariable,
        sarifPath: out,
        exclusive: OPENGREP_GROUP,
        // Like the semgrep engine: exit 0 with or without findings; anything else is a failure.
        okExitCodes: [0],
        version: null,
        transform: (output: unknown) => {
          warnOtherOpengrep(output, pack.manifest, ctx);
          withQualorRules(output, pack.manifest);
          dropResultsOn(output, tests, ctx.root);
          if (engine !== null) withTaintEngineRuns(output, engine.sarif, ctx.root, byEngine);
          return output;
        },
        ...(salvage !== undefined && { salvage }),
        ...(fallbackWarnings.length > 0 && { warnings: fallbackWarnings }),
      },
    };
  };
  return {
    id: 'qualor',
    languages: QUALOR_LANGUAGES,
    // The rules apply to these languages only (report-format §5), so language profiles govern them.
    ruleLanguages: QUALOR_LANGUAGES,
    prepare: async (ctx) => {
      const prep = prepare(ctx);
      // Plan 6B-6: never unpacking OpenGrep at the same time as another qualor scan.
      if ('run' in prep) await warmOpengrep(ctx, prep.run.command);
      return prep;
    },
  };
}

export const qualorAnalyzer = createQualorAnalyzer();
