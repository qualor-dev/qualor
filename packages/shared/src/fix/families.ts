/**
 * Fix MRs (0.16, spec §6, B7): the families a fix is made for, the files a fix may change, and the
 * fixed limits, failure codes and no-fix reasons the CLI and the server share.
 */

/** B7: a fix is identified by `(project, family, package)`. */
export const FIX_FAMILIES = ['js', 'go', 'maven', 'python'] as const;
export type FixFamily = (typeof FIX_FAMILIES)[number];

/** The Trivy package types Qualor fixes, by family; any other type has no automatic fix. */
export const FIX_ECOSYSTEM_FAMILY: Readonly<Record<string, FixFamily>> = Object.freeze({
  npm: 'js',
  pnpm: 'js',
  yarn: 'js',
  gomod: 'go',
  pom: 'maven',
  uv: 'python',
  poetry: 'python',
});

/** The family of a Trivy package type; null when Qualor has no automatic fix for it. */
export function familyOfEcosystem(ecosystem: string): FixFamily | null {
  return Object.hasOwn(FIX_ECOSYSTEM_FAMILY, ecosystem)
    ? (FIX_ECOSYSTEM_FAMILY[ecosystem] ?? null)
    : null;
}

/** The Trivy package types of a family. */
export function ecosystemsOf(family: FixFamily): string[] {
  return Object.entries(FIX_ECOSYSTEM_FAMILY)
    .filter(([, f]) => f === family)
    .map(([ecosystem]) => ecosystem);
}

export interface FixFileNames {
  readonly manifests: readonly string[];
  readonly lockfiles: readonly string[];
}

const files = (manifests: string[], lockfiles: string[]): FixFileNames =>
  Object.freeze({ manifests: Object.freeze(manifests), lockfiles: Object.freeze(lockfiles) });

/** §6.7: the only files a fix upload may change, by basename. Maven has no lockfile. */
export const FIX_FILES: Readonly<Record<FixFamily, FixFileNames>> = Object.freeze({
  js: files(
    ['package.json', 'pnpm-workspace.yaml'],
    ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'],
  ),
  go: files(['go.mod'], ['go.sum']),
  maven: files(['pom.xml'], []),
  python: files(['pyproject.toml'], ['uv.lock', 'poetry.lock']),
});

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

/** Whether a path names a manifest or a lockfile of the family, by its basename. */
export function fixFileKind(family: FixFamily, path: string): 'manifest' | 'lockfile' | null {
  const name = basename(path);
  if (FIX_FILES[family].manifests.includes(name)) return 'manifest';
  if (FIX_FILES[family].lockfiles.includes(name)) return 'lockfile';
  return null;
}

const MAX_PATH_CHARS = 1024;

function segmentProblem(segment: string): string | null {
  if (segment === '') return 'empty path segment';
  if (segment === '.' || segment === '..') return '"." or ".." path segment';
  if (segment.toLowerCase() === '.git') return 'path under .git';
  return null;
}

/**
 * §6.7: what is wrong with a path a fix upload names, as a fixed text (the first failing rule), or
 * null for a relative, normalised path to a manifest or lockfile of the family outside `.git`.
 */
export function fixPathProblem(family: FixFamily, path: string): string | null {
  if (path === '') return 'empty path';
  if (path.length > MAX_PATH_CHARS) return `path longer than ${MAX_PATH_CHARS} characters`;
  if (path.startsWith('/') || /^[A-Za-z]:/.test(path)) return 'absolute path';
  if (path.includes('\\')) return 'backslash in path';
  for (const segment of path.split('/')) {
    const problem = segmentProblem(segment);
    if (problem !== null) return problem;
  }
  return fixFileKind(family, path) === null ? `not a ${family} manifest or lockfile` : null;
}

/** §6.5, §6.7: the fixed limits of fixes. */
export const FIX_LIMITS = {
  /** Files in one upload. */
  maxFiles: 50,
  /** Bytes of all files of one upload together. */
  maxTotalBytes: 32 * 1024 * 1024,
  /** Bytes of a failure message kept (the tail). */
  messageBytes: 2048,
  /** A claimed fix's lease. */
  leaseMinutes: 30,
  /** The CLI's time for one fix. */
  perFixMinutes: 10,
  /** Open fix MRs per project unless set. */
  defaultMaxOpen: 5,
  /** The highest per-project cap of open fix MRs. */
  maxOpen: 20,
  /** Fixes one claim may hand out. */
  claimMax: 10,
} as const;

/** §6.4: why a fix failed (`failure.code`). */
export const FIX_FAILURE_CODES = [
  'manifest_unsupported',
  'missing_tool',
  'package_manager',
  'verify_failed',
  'unplanned_change',
  'timeout',
  'upload_refused',
  'scm_permission',
  'scm_refused',
  'scm_unavailable',
  'scm_not_bound',
  'fixes_disabled',
] as const;
export type FixFailureCode = (typeof FIX_FAILURE_CODES)[number];

/** §6.4, B3, B4: why a fix ended with nothing to change (`no_fix`). */
export const NO_FIX_REASONS = [
  'no_fixed_version',
  'declined',
  'several_lines',
  'not_installed',
  'unresolvable',
] as const;
export type NoFixReason = (typeof NO_FIX_REASONS)[number];
