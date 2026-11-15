import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  normalizeLicense,
  normalizeRepoPath,
  REPORT_BOUNDS,
  type DependencyEntry,
  type NormalizeWarning,
} from '@qualor/shared';
import { z } from 'zod';
import { deadProxyEnv } from './offline';
import { isTrivyVariable } from './trivy';
import { findPackageLine, lockfileLines, versionLine } from './trivy-output';
import type { AnalyzerCommand, AnalyzerContext } from './types';

/** The report's engine entry for the licence pass (spec §1): it makes no findings. */
export const LICENSE_ENGINE_ID = 'trivy-licenses';

/** Report bounds of `dependencies` (spec §2, report-format.md). */
export const MAX_DEPENDENCIES: number = REPORT_BOUNDS.dependencies;
const MAX_LICENSES = 16;
const MAX_LICENSE_CHARS = 256;
const MAX_PATH_CHARS = 1_024;
const MAX_NAME_CHARS = 512;
const MAX_VERSION_CHARS = 256;
const ECOSYSTEM = /^[a-z0-9-]{1,32}$/;

/**
 * The variables naming where installed packages live, passed to Trivy as the CLI got them: without
 * GOPATH Trivy reads no Go licence and without the NuGet package folder no NuGet one, silently
 * (6M probe). HOME and USERPROFILE locate `~/go` and `~/.nuget/packages`.
 */
const PACKAGE_CACHE_VARIABLES = ['GOPATH', 'GOMODCACHE', 'NUGET_PACKAGES', 'HOME', 'USERPROFILE'];

/**
 * The user's directory excludes (`<dir>/**`) as Trivy `--skip-dirs` globs, as the vulnerability
 * pass passes the built-in ones: Trivy need not read what the scan leaves out. Other globs only
 * drop targets afterwards (`trivyJsonToInventory`'s `exclude`).
 */
export function licenseSkipDirs(exclude: readonly string[]): string[] {
  return exclude.filter((g) => g.endsWith('/**') && g.length > 3).map((g) => g.slice(0, -3));
}

/** The licence pass's own environment additions: the dead proxy and the package caches. */
function licenseEnv(env: AnalyzerContext['env']): Record<string, string> {
  const out: Record<string, string> = { ...deadProxyEnv() };
  for (const name of PACKAGE_CACHE_VARIABLES) {
    const value = env[name];
    if (value !== undefined && value !== '') out[name] = value;
  }
  // Trivy finds the Go module cache only through GOPATH: `go` itself defaults it to ~/go.
  if (out['GOPATH'] === undefined) {
    const home = out['HOME'] ?? out['USERPROFILE'];
    if (home !== undefined && existsSync(path.join(home, 'go', 'pkg', 'mod'))) {
      out['GOPATH'] = path.join(home, 'go');
    }
  }
  return out;
}

/**
 * The second Trivy run (spec §1): the vulnerability pass's flags (an empty config, offline, no
 * telemetry, no WebAssembly modules, every `TRIVY_*` variable dropped, the dead proxy) with
 * `--scanners license` instead of `vuln`, and no `.trivyignore` (it lists vulnerability ids). Of
 * the vulnerability pass's `--skip-dirs` it keeps the directory excludes and the database cache
 * inside the checkout (`ctx.trivyCacheSkipDir`), not the built-in ones: pnpm's and Go's licences
 * are read from `node_modules` and the module cache. It needs no vulnerability database
 * (`cacheDir` may be empty). Writes Trivy's empty config and module directory into `ctx.workDir`.
 */
export function licenseCommand(ctx: AnalyzerContext, cacheDir: string): AnalyzerCommand {
  const emptyConfig = path.join(ctx.workDir, 'trivy-licenses.yaml');
  const modules = path.join(ctx.workDir, 'licenses-modules');
  writeFileSync(emptyConfig, '');
  mkdirSync(modules, { recursive: true });
  const out = path.join(ctx.workDir, 'licenses.json');
  const timeout = ctx.config.analyzers.trivy.licenseTimeoutSeconds;
  const inRepository = ctx.trivyCacheSkipDir ?? null;
  return {
    command: ctx.resolveBinary('trivy') ?? 'trivy',
    args: [
      'fs',
      '--config',
      emptyConfig,
      '--cache-dir',
      cacheDir,
      '--cache-backend',
      'memory',
      '--skip-db-update',
      '--skip-java-db-update',
      '--skip-vex-repo-update',
      '--skip-check-update',
      '--offline-scan',
      '--skip-version-check',
      '--disable-telemetry',
      '--module-dir',
      modules,
      '--scanners',
      'license',
      '--pkg-types',
      'library',
      '--list-all-pkgs',
      // The scan's database cache inside the checkout holds the archive, not the project's lockfiles.
      ...[
        ...licenseSkipDirs(ctx.config.sources.exclude),
        ...(inRepository === null ? [] : [inRepository]),
      ].flatMap((d) => ['--skip-dirs', d]),
      '--timeout',
      `${timeout}s`,
      '--format',
      'json',
      '--output',
      out,
      '--quiet',
      '.',
    ],
    cwd: ctx.root,
    env: licenseEnv(ctx.env),
    dropEnv: isTrivyVariable,
    sarifPath: out,
    okExitCodes: [0],
    version: null,
  };
}

const location = z.looseObject({
  StartLine: z.number().int().positive().optional(),
  EndLine: z.number().int().positive().optional(),
});
const licensePackage = z.looseObject({
  Name: z.string().optional(),
  Version: z.string().optional(),
  Licenses: z.array(z.string()).optional(),
  Relationship: z.string().optional(),
  Indirect: z.boolean().optional(),
  Locations: z.array(location).optional(),
});
const licenseResult = z.looseObject({
  Target: z.string(),
  Class: z.string().optional(),
  Type: z.string().optional(),
  Packages: z.array(licensePackage).optional(),
});
/** `trivy fs --scanners license --list-all-pkgs --format json`, the fields the inventory uses. */
export const trivyLicenseReportSchema = z.looseObject({
  SchemaVersion: z.literal(2),
  Trivy: z.looseObject({ Version: z.string().optional() }).optional(),
  Results: z.array(licenseResult).optional(),
});

type LicensePackage = z.infer<typeof licensePackage>;

/**
 * Ruling of the 6M probe: Trivy's `Relationship` when it gives one (`root` is the project itself
 * and is dropped by the caller), else `Indirect: true` (never written as false), else unknown.
 */
function directOf(p: LicensePackage): boolean | undefined {
  if (p.Relationship === 'direct') return true;
  if (p.Relationship === 'indirect') return false;
  return p.Indirect === true ? false : undefined;
}

/** Licence strings left out of entries (`trivyJsonToInventory`, `mergeDuplicates`). */
export interface LicenseStats {
  licensesDropped: number;
}

/**
 * The `DEPENDENCY_LICENSES_SKIPPED` warning: licence strings an entry could not carry. A long SPDX
 * expression is never cut (cut short, `A OR … OR MIT` could lose its permissive alternative), and
 * licences are AND-combined, so the ones beyond 16 could hold the forbidden one: both are counted.
 */
export function licensesSkippedWarning(count: number): NormalizeWarning {
  return {
    code: 'DEPENDENCY_LICENSES_SKIPPED',
    message: `${count} licence strings were left out of the inventory: longer than ${MAX_LICENSE_CHARS} characters (a shortened expression could change its meaning) or beyond ${MAX_LICENSES} for one package, so those packages' licences are incomplete`,
    count,
  };
}

/**
 * Normalised (§3), sorted, unique; a string over 256 characters is dropped, never cut, and at most
 * 16 are kept. What is dropped is counted in `stats`; nothing left is `[]`, unknown.
 */
function licenseList(raw: readonly string[], stats: LicenseStats): string[] {
  const normalised = new Set(raw.map((l) => normalizeLicense(l)).filter((l) => l !== ''));
  const fitting = [...normalised].filter((l) => l.length <= MAX_LICENSE_CHARS).sort();
  stats.licensesDropped += normalised.size - Math.min(fitting.length, MAX_LICENSES);
  return fitting.slice(0, MAX_LICENSES);
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The `go.mod` line requiring `name` at `version` (`require name version` or, inside a `require`
 * block, `name version`, with an optional `// indirect`): Trivy gives Go packages no position, and
 * `findPackageLine` looks for `name@version`. 1-based, or null.
 */
export function goModLine(lines: readonly string[], name: string, version: string): number | null {
  const re = new RegExp(`^\\s*(?:require\\s+)?${escape(name)}\\s+${escape(version)}\\s*(?://.*)?$`);
  const at = lines.findIndex((l) => re.test(l));
  return at === -1 ? null : at + 1;
}

export interface InventoryOptions {
  /** `sources.exclude` and the built-in excludes: a lockfile they match is left out silently. */
  exclude?: (repoPath: string) => boolean;
  /**
   * The scan's files (the report's `files`), the analyzers' `knownPaths`: a lockfile outside them
   * is left out and counted in `DEPENDENCIES_OUT_OF_SCOPE`, as the vulnerability pass drops a
   * finding there with `FINDING_OUT_OF_SCOPE`. Absent, every lockfile is kept.
   */
  knownPaths?: ReadonlySet<string>;
}

/** The repository path of a Trivy target, or null when it is not one. */
function targetPath(target: string, root: string): string | null {
  try {
    const p = normalizeRepoPath(target, root);
    return p === '' ? null : p;
  } catch {
    return null;
  }
}

/**
 * Trivy's licence JSON as the report's dependency inventory (spec §1): every package of every
 * `Class: lang-pkgs` result (the separate `Class: license` results are ignored), the root project
 * dropped. The line is the version line inside Trivy's range of the package's lock entry (ruling
 * T3), else the `name@version` search of the lockfile, else (Go) the `go.mod` requirement. An entry
 * the report could not carry (an over-long name, version or path, an unusable ecosystem or path) is
 * skipped and counted in one `DEPENDENCIES_SKIPPED` warning; a licence string it could not carry
 * is dropped and counted in `DEPENDENCY_LICENSES_SKIPPED`. A lockfile the scan does not analyse
 * (not in `knownPaths`: gitignored or excluded, such as an in-repository Go module cache) is left
 * out and counted in `DEPENDENCIES_OUT_OF_SCOPE`; one that `exclude` matches (`sources.exclude`, the
 * built-in excludes such as a .NET build's `bin/Debug/`) is left out silently.
 * Throws on output that is not Trivy's JSON report. Entries are neither merged nor capped here
 * (`mergeDuplicates`, `capInventory`).
 */
export function trivyJsonToInventory(
  output: unknown,
  root: string,
  o: InventoryOptions = {},
): { entries: DependencyEntry[]; warnings: NormalizeWarning[] } {
  const report = trivyLicenseReportSchema.parse(output);
  const tally: InventoryTally = {
    entries: [],
    stats: { licensesDropped: 0 },
    skipped: 0,
    outOfScope: 0,
    outOfScopePaths: new Set<string>(),
  };
  for (const result of report.Results ?? []) addResultEntries(result, root, o, tally);
  return { entries: tally.entries, warnings: inventoryWarnings(tally) };
}

type LicenseResult = z.infer<typeof licenseResult>;

/** What `trivyJsonToInventory` gathers across Trivy's results. */
interface InventoryTally {
  entries: DependencyEntry[];
  stats: LicenseStats;
  skipped: number;
  outOfScope: number;
  outOfScopePaths: Set<string>;
}

/**
 * One Trivy result's packages into `tally`: nothing for a result that is not `lang-pkgs`, has no
 * package beyond the root project or is excluded; counted out of scope or skipped when the
 * lockfile cannot be carried.
 */
function addResultEntries(
  result: LicenseResult,
  root: string,
  o: InventoryOptions,
  tally: InventoryTally,
): void {
  if (result.Class !== 'lang-pkgs') return;
  const packages = (result.Packages ?? []).filter((p) => p.Relationship !== 'root');
  if (packages.length === 0) return;
  const ecosystem = result.Type ?? '';
  const repoPath = targetPath(result.Target, root);
  if (repoPath !== null && o.exclude?.(repoPath) === true) return;
  if (repoPath !== null && o.knownPaths !== undefined && !o.knownPaths.has(repoPath)) {
    tally.outOfScope += packages.length;
    tally.outOfScopePaths.add(repoPath);
    return;
  }
  if (!ECOSYSTEM.test(ecosystem) || repoPath === null || repoPath.length > MAX_PATH_CHARS) {
    tally.skipped += packages.length;
    return;
  }
  const lines = lazyLockfileLines(root, repoPath);
  for (const p of packages) {
    const name = p.Name ?? '';
    const version = p.Version ?? '';
    if (name === '' || name.length > MAX_NAME_CHARS || version.length > MAX_VERSION_CHARS) {
      tally.skipped += 1;
      continue;
    }
    const line = lineOf(p, ecosystem, name, version, lines);
    const direct = directOf(p);
    tally.entries.push({
      ecosystem,
      path: repoPath,
      ...(line !== null && { line }),
      name,
      version,
      licenses: licenseList(p.Licenses ?? [], tally.stats),
      ...(direct !== undefined && { direct }),
    });
  }
}

/** The lockfile's lines, read once on first use: most packages carry Trivy's own position. */
function lazyLockfileLines(root: string, repoPath: string): () => readonly string[] | null {
  let cached: readonly string[] | null | undefined;
  return () => {
    if (cached === undefined) cached = lockfileLines(root, repoPath);
    return cached;
  };
}

/** The inventory's warnings: the skipped and out-of-scope dependencies, the dropped licences. */
function inventoryWarnings(tally: InventoryTally): NormalizeWarning[] {
  const { skipped, outOfScope, outOfScopePaths, stats } = tally;
  const warnings: NormalizeWarning[] = [];
  if (skipped > 0) {
    warnings.push({
      code: 'DEPENDENCIES_SKIPPED',
      message: `${skipped} dependencies were left out of the inventory: a name, version or lockfile path longer than the report allows, or a package type it does not accept`,
      count: skipped,
    });
  }
  if (outOfScope > 0) {
    warnings.push({
      code: 'DEPENDENCIES_OUT_OF_SCOPE',
      message: `${outOfScope} dependencies from ${outOfScopePaths.size} lockfiles outside the analysis scope (gitignored or excluded, such as an in-repository package cache) were left out of the inventory`,
      count: outOfScope,
    });
  }
  if (stats.licensesDropped > 0) warnings.push(licensesSkippedWarning(stats.licensesDropped));
  return warnings;
}

function lineOf(
  p: LicensePackage,
  ecosystem: string,
  name: string,
  version: string,
  lines: () => readonly string[] | null,
): number | null {
  const at = p.Locations?.find((l) => l.StartLine !== undefined);
  if (at?.StartLine !== undefined) {
    const end = at.EndLine !== undefined && at.EndLine >= at.StartLine ? at.EndLine : at.StartLine;
    const found = lines();
    return (
      (found === null ? null : versionLine(found, ecosystem, at.StartLine, end, version)) ??
      at.StartLine
    );
  }
  const found = lines();
  if (found === null) return null;
  return (
    findPackageLine(found, name, version) ??
    (ecosystem === 'gomod' ? goModLine(found, name, version) : null)
  );
}

const keyOf = (e: DependencyEntry) => `${e.path}\0${e.ecosystem}\0${e.name}\0${e.version}`;

/**
 * Spec §2: one entry per `(path, ecosystem, name, version)`, with the union of the licences
 * (sorted, unique, at most 16; the ones beyond are counted in `stats`), the first line and `direct`
 * when any says so. First-seen order.
 */
export function mergeDuplicates(
  entries: readonly DependencyEntry[],
  stats: LicenseStats = { licensesDropped: 0 },
): DependencyEntry[] {
  const merged = new Map<string, DependencyEntry>();
  for (const e of entries) {
    const key = keyOf(e);
    const seen = merged.get(key);
    if (seen === undefined) {
      merged.set(key, { ...e, licenses: [...e.licenses] });
      continue;
    }
    const union = [...new Set([...seen.licenses, ...e.licenses])].sort();
    stats.licensesDropped += Math.max(0, union.length - MAX_LICENSES);
    seen.licenses = union.slice(0, MAX_LICENSES);
    if (e.line !== undefined && (seen.line === undefined || e.line < seen.line)) seen.line = e.line;
    if (e.direct === true || (e.direct === false && seen.direct === undefined)) {
      seen.direct = e.direct;
    }
  }
  return [...merged.values()];
}

function compare(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/**
 * Spec §2: the inventory in report order (the direct dependencies first, then by path, name and
 * version), at most `max` entries; `truncated` when some were left out.
 */
export function capInventory(
  entries: readonly DependencyEntry[],
  max = MAX_DEPENDENCIES,
): { entries: DependencyEntry[]; truncated: boolean } {
  const sorted = [...entries].sort(
    (a, b) =>
      Number(b.direct === true) - Number(a.direct === true) ||
      compare(a.path, b.path) ||
      compare(a.name, b.name) ||
      compare(a.version, b.version) ||
      compare(a.ecosystem, b.ecosystem),
  );
  return { entries: sorted.slice(0, max), truncated: sorted.length > max };
}
