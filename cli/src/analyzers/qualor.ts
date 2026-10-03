import { createHash } from 'node:crypto';
import { existsSync, lstatSync, opendirSync, readFileSync, type Dir, type Stats } from 'node:fs';
import path from 'node:path';
import {
  QUALOR_KIND_PROPERTY,
  QUALOR_SEVERITY_PROPERTY,
  qualorManifestSchema,
  qualorRuleId,
  type Language,
  type QualorManifest,
} from '@qualor/shared';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { isInside } from './binary';
import { deadProxyEnv } from './offline';
import { shown } from './reason';
import { isObject, isOpengrepVariable, MAX_RULE_FILE_BYTES, offlineFlags } from './semgrep';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where the qualor/scanner image installs Qualor's security rules (install-qualor-rules.sh). */
export const DEFAULT_QUALOR_RULES_DIR = '/opt/qualor/rules/qualor';

/** The languages of the pack's rules: `js` covers JavaScript and TypeScript. */
export const QUALOR_LANGUAGES: readonly Language[] = [
  'javascript',
  'typescript',
  'python',
  'java',
  'go',
];

export const QUALOR_RULES_NOT_INSTALLED =
  "Qualor's security rules are not installed (they ship in the qualor/scanner image)";

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
  const files: string[] = [];
  const stack = ['rules'];
  let entries = 0;
  while (stack.length > 0) {
    const rel = stack.pop() as string;
    let handle: Dir;
    try {
      handle = opendirSync(path.join(dir, ...rel.split('/')));
    } catch {
      return { problem: 'the rules pack cannot be read' };
    }
    try {
      for (let e = handle.readSync(); e !== null; e = handle.readSync()) {
        entries += 1;
        if (entries > MAX_PACK_ENTRIES) return { problem: 'the rules pack has too many files' };
        const child = `${rel}/${e.name}`;
        if (e.isSymbolicLink()) {
          return { problem: `the rules pack holds a symbolic link (${shown(child)})` };
        }
        if (e.isDirectory()) stack.push(child);
        else files.push(child);
      }
    } finally {
      handle.closeSync();
    }
  }
  return { files: files.sort() };
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

/**
 * config.md §6: OpenGrep's SARIF made Qualor's. Rule ids `<lang>.<name>` become `<lang>/<name>`;
 * a rule the manifest lists gets its title as the short description and its kind and severity as
 * properties (report-format.md §7.1); in-source suppressions (`nosem` comments in the checkout) are
 * removed; the driver version names the pack. Mutates and returns `output`; anything that is not a
 * SARIF log is returned as it is.
 */
export function withQualorRules(output: unknown, manifest: QualorManifest): unknown {
  if (!isObject(output) || !Array.isArray(output['runs'])) return output;
  const byId = new Map(manifest.rules.map((r) => [r.id, r]));
  for (const run of output['runs']) {
    if (!isObject(run)) continue;
    const tool = run['tool'];
    const driver = isObject(tool) ? tool['driver'] : undefined;
    if (isObject(driver)) {
      const engine =
        typeof driver['semanticVersion'] === 'string'
          ? driver['semanticVersion']
          : typeof driver['version'] === 'string'
            ? driver['version']
            : 'OpenGrep';
      driver['version'] = `${engine} + qualor-rules ${manifest.version}`;
      for (const rule of Array.isArray(driver['rules']) ? driver['rules'] : []) {
        if (!isObject(rule) || typeof rule['id'] !== 'string') continue;
        const id = qualorRuleId(rule['id']);
        if (id === null) continue;
        rule['id'] = id;
        rule['name'] = id;
        const entry = byId.get(id);
        if (entry === undefined) continue;
        rule['shortDescription'] = { text: entry.title };
        rule['properties'] = {
          ...(isObject(rule['properties']) ? rule['properties'] : {}),
          [QUALOR_KIND_PROPERTY]: entry.kind,
          [QUALOR_SEVERITY_PROPERTY]: entry.severity,
        };
      }
    }
    for (const result of Array.isArray(run['results']) ? run['results'] : []) {
      if (!isObject(result)) continue;
      if (typeof result['ruleId'] === 'string') {
        result['ruleId'] = qualorRuleId(result['ruleId']) ?? result['ruleId'];
      }
      const suppressions = result['suppressions'];
      if (!Array.isArray(suppressions)) continue;
      const kept = suppressions.filter((s) => !(isObject(s) && s['kind'] === 'inSource'));
      if (kept.length > 0) result['suppressions'] = kept;
      else delete result['suppressions'];
    }
  }
  return output;
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

export function createQualorAnalyzer(
  o: { defaultDir?: string; maxTargetArgBytes?: number } = {},
): Analyzer {
  const defaultDir = o.defaultDir ?? DEFAULT_QUALOR_RULES_DIR;
  const budget = o.maxTargetArgBytes ?? MAX_TARGET_ARG_BYTES;
  const prepare = (ctx: AnalyzerContext): Preparation => {
    const fromEnv = ctx.env['QUALOR_RULES_DIR'];
    const dir = fromEnv || defaultDir;
    if (!path.isAbsolute(dir) || isInside(ctx.root, dir)) {
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
    if ('problem' in pack) return { unavailable: pack.problem };
    const files = ctx.files
      .filter((f) => QUALOR_LANGUAGES.includes(f.language))
      .map((f) => path.relative(ctx.root, f.absPath).split(path.sep).join('/'));
    if (files.length === 0) {
      return { skip: 'no JavaScript, TypeScript, Python, Java or Go files in scope' };
    }
    // Plan 6B-1: only the OpenGrep the pack is tested with, never Semgrep.
    const opengrep = ctx.resolveBinary('opengrep');
    if (opengrep === null) return { unavailable: 'OpenGrep is not installed' };
    // Named files are scanned whatever .gitignore, .semgrepignore or OpenGrep's own ignores say.
    const explicit = files.reduce((n, f) => n + Buffer.byteLength(f) + 1, 0) <= budget;
    if (!explicit) {
      ctx.log.warn(
        `qualor: ${files.length} files do not fit one command line; OpenGrep selects the files itself and findings outside the scan's scope are dropped`,
      );
    }
    const out = path.join(ctx.workDir, 'qualor.sarif');
    return {
      run: {
        command: opengrep,
        args: [
          'scan',
          '--config',
          path.join(pack.dir, 'rules'),
          '--sarif',
          '--output',
          out,
          ...offlineFlags('opengrep'),
          ...(explicit
            ? ['--', ...files]
            : [
                // Below `.` the tool skips files over 1,000,000 bytes silently; named files are
                // always scanned.
                '--max-target-bytes',
                String(MAX_ANALYZED_BYTES),
                '--x-ignore-semgrepignore-files',
                '.',
              ]),
        ],
        cwd: ctx.root,
        env: deadProxyEnv(),
        dropEnv: isOpengrepVariable,
        sarifPath: out,
        // Like the semgrep engine: exit 0 with or without findings; anything else is a failure.
        okExitCodes: [0],
        version: null,
        transform: (output: unknown) => {
          const engine = opengrepVersion(output);
          if (engine !== null && engine !== pack.manifest.opengrep) {
            ctx.log.warn(
              `qualor: the rules pack ${pack.manifest.version} is tested with OpenGrep ${pack.manifest.opengrep}, not ${engine}`,
            );
          }
          return withQualorRules(output, pack.manifest);
        },
      },
    };
  };
  return {
    id: 'qualor',
    languages: QUALOR_LANGUAGES,
    // The rules apply to these languages only (report-format §5), so language profiles govern them.
    ruleLanguages: QUALOR_LANGUAGES,
    prepare: (ctx) => Promise.resolve(prepare(ctx)),
  };
}

export const qualorAnalyzer = createQualorAnalyzer();
