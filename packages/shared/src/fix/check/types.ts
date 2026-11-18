/**
 * Content checks of a fix upload (spec §12 B1): the server re-reads every uploaded manifest and
 * lockfile and compares it with the same file at `baseSha`. These are the shared shapes and the
 * fixed rule texts a refusal (422 `UPLOAD_REFUSED`) names.
 */
import type { FixFamily } from '../families';

/** One uploaded file: its path, its text at `baseSha` and its uploaded text. */
export interface FixFileChange {
  path: string;
  base: string;
  next: string;
}

/** B3: the target of one installed version, in one lockfile. */
export interface FixTarget {
  installed: string;
  target: string;
  lockfile: string;
}

/** The rules a content check can fail, in no particular order. */
export const FIX_RULES = [
  'unparsable',
  'other_change',
  'new_dependency',
  'bad_spec',
  'new_source',
  'source_kind',
  'missing_integrity',
  'below_target',
  'go_directive',
] as const;
export type FixRule = (typeof FIX_RULES)[number];

/** The fixed text of each rule, as the refusal names it. */
export const FIX_RULE_TEXT: Record<FixRule, string> = Object.freeze({
  unparsable: 'A changed file cannot be read in its format.',
  other_change: "The change touches more than the package's version and its pin.",
  new_dependency: 'The change adds a dependency other than the package being fixed.',
  bad_spec: 'The new requirement is not a plain version or version range.',
  new_source: 'A lockfile entry comes from a host the lockfile did not use.',
  source_kind: 'A new lockfile entry comes from a git, file, link, path or tarball source.',
  missing_integrity: 'A new lockfile entry has no integrity hash.',
  below_target: 'The package still resolves below its fixed version.',
  go_directive: 'go.mod changes a directive other than require.',
});

/** The outcome of a content check: the first failing rule and the file it failed on. */
export type FixCheckResult = { ok: true } | { ok: false; rule: FixRule; path: string };

/** What a content check knows of the fix. */
export interface FixCheckContext {
  family: FixFamily;
  packageName: string;
  targets: readonly FixTarget[];
}

/** One resolved package of a lockfile, in a form shared by every format. */
export interface LockEntry {
  /** The package actually fetched. */
  name: string;
  /**
   * The name the package is installed and depended on as, when that differs from `name` (an
   * alias: an npm folder, a Yarn pattern or descriptor, a pnpm reference); absent otherwise.
   */
  slot?: string;
  version: string;
  /** Where it is fetched from (a URL, a path or a reference); null when the format names none. */
  source: string | null;
  kind: 'registry' | 'git' | 'file' | 'link' | 'tarball' | 'path' | 'other';
  integrity: string | null;
  /** The names of the packages that depend on this package's name, sorted. */
  dependents: string[];
}

export type LockEntryKind = LockEntry['kind'];

export const FIX_CHECK_OK: FixCheckResult = Object.freeze({ ok: true });

export function fixRefused(rule: FixRule, path: string): FixCheckResult {
  return { ok: false, rule, path };
}
