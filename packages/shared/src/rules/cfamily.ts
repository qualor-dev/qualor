import type { Quality, Severity } from '../report/taxonomy';

/**
 * C and C++ (plan 9D, config.md §6.2). `CPPCHECK_VERSION` is the cppcheck the qualor/scanner
 * image builds (tools/analyzers/install-cppcheck.sh; tools/ci.test.ts checks they agree). The CLI
 * runs only a cppcheck of the same major.minor: analysis-error ids and severities change between
 * minors.
 */
export const CPPCHECK_VERSION = '2.22.0';

/** cppcheck's `--enable` groups Qualor lets a project choose (`error` is always on). */
export const CPPCHECK_ENABLE_GROUPS = ['warning', 'style', 'performance', 'portability'] as const;
export type CppcheckEnableGroup = (typeof CPPCHECK_ENABLE_GROUPS)[number];
/** Decision 4: `style` multiplies jq's findings by nine (fact F6). */
export const DEFAULT_CPPCHECK_ENABLE: readonly CppcheckEnableGroup[] = [
  'warning',
  'performance',
  'portability',
];

/**
 * Ruling D9-14: ids Qualor turns off by default (52 of fmt's 59 findings, mostly false positives on
 * union members). `analyzers.cppcheck.select` lists ids to turn back on.
 */
export const DEFAULT_CPPCHECK_SUPPRESSED = [
  'uninitMemberVar',
  'uninitMemberVarPrivate',
  'uninitMemberVarNoCtor',
] as const;

/** The default-suppressed ids that a project's `select` did not turn back on. */
export function cppcheckSuppressed(select: readonly string[]): string[] {
  return DEFAULT_CPPCHECK_SUPPRESSED.filter((id) => !select.includes(id));
}

/**
 * Ids that say cppcheck could not analyse (part of) a file, or report on the run itself: never a
 * finding (decision 6), counted in one warn line instead.
 */
export const CPPCHECK_ANALYSIS_IDS: ReadonlySet<string> = new Set([
  'syntaxError',
  'unknownMacro',
  'internalAstError',
  'internalError',
  'preprocessorErrorDirective',
  'cppcheckError',
  'instantiationError',
  'templateRecursion',
  'unhandledChar',
  'missingInclude',
  'missingIncludeSystem',
  'toomanyconfigs',
  'purgedConfiguration',
  'checkersReport',
  'normalCheckLevelMaxBranches',
  'checkLevelNormal',
  'unmatchedSuppression',
  'noValidConfiguration',
]);
const NO_FINDING_SEVERITIES = new Set(['information', 'debug', 'internal', 'none']);

export function cppcheckIsFinding(id: string, severity: string): boolean {
  return !CPPCHECK_ANALYSIS_IDS.has(id) && !NO_FINDING_SEVERITIES.has(severity);
}

/** `cppcheck --version` prints `Cppcheck 2.22.0` (or `Cppcheck 2.18` for some `.0` releases). */
export function cppcheckVersionSupported(version: string): boolean {
  const [major, minor] = CPPCHECK_VERSION.split('.');
  const m = /^(\d+)\.(\d+)(?:\.\d+)?$/.exec(version);
  return m !== null && m[1] === major && m[2] === minor;
}

/** report-format.md §7.1. */
export function cppcheckSeverity(severity: string): Severity {
  if (severity === 'error') return 'high';
  if (severity === 'style' || severity === 'performance' || severity === 'portability')
    return 'low';
  return 'medium';
}

export function cppcheckQuality(severity: string): Quality {
  return severity === 'error' || severity === 'warning' ? 'reliability' : 'maintainability';
}

/** The oldest clang-tidy the engine runs: Debian bookworm's LLVM 14 (fact F7). */
export const CLANG_TIDY_MIN_MAJOR = 14;

/** `version` as `clang-tidy --version` prints it after `LLVM version ` (`22.1.8`). */
export function clangTidyVersionSupported(version: string): boolean {
  const m = /^(\d+)\.\d+\.\d+/.exec(version);
  return m !== null && Number(m[1]) >= CLANG_TIDY_MIN_MAJOR;
}

/**
 * Decision 4 and fact F8: the bug-finding groups, without the checks that flooded fmt and without
 * `misc-*`/`cert-*` (mostly style, or aliases of bugprone checks).
 */
export const CLANG_TIDY_DEFAULT_CHECKS = [
  '-*',
  'bugprone-*',
  '-bugprone-easily-swappable-parameters',
  '-bugprone-narrowing-conversions',
  'clang-analyzer-*',
  '-clang-analyzer-optin.*',
  'performance-*',
  '-performance-enum-size',
  'portability-*',
  'concurrency-*',
  '-concurrency-mt-unsafe',
].join(',');

/** clang-tidy's own default when a `.clang-tidy` names no `Checks`. */
export const CLANG_TIDY_BUILTIN_CHECKS = 'clang-diagnostic-*,clang-analyzer-*';

/** report-format.md §7.1: quality and severity from the check's group. */
export function clangTidyMeta(check: string): { quality: Quality; severity: Severity } {
  if (
    check.startsWith('clang-analyzer-security.') ||
    check.startsWith('clang-analyzer-optin.taint.')
  ) {
    return { quality: 'security', severity: 'high' };
  }
  if (check.startsWith('clang-analyzer-')) return { quality: 'reliability', severity: 'high' };
  if (
    check.startsWith('clang-diagnostic-') ||
    check.startsWith('bugprone-') ||
    check.startsWith('cert-') ||
    check.startsWith('concurrency-')
  ) {
    return { quality: 'reliability', severity: 'medium' };
  }
  return { quality: 'maintainability', severity: 'low' };
}
