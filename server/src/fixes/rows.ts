import { FIX_FAMILIES, normalizePythonName, type FixFamily } from '@qualor/shared/fix';
import { z } from 'zod';
import { FIX_STATES, type dependencyFixes } from '../db/schema';
import { iso, timestamp } from '../http/schemas';

export type DependencyFixRow = typeof dependencyFixes.$inferSelect;

/**
 * R12, spec §6.8: a package's fix as the vulnerability items and the Trivy issues of main embed
 * it. Never the branch, the lease or the uploaded files.
 */
export const dependencyFixSchema = z.object({
  id: z.uuid(),
  state: z.enum(FIX_STATES),
  /** An open MR that a fix job rebuilds from the current main (a conflict, a higher target). */
  refresh: z.boolean(),
  /** The greatest target version of the last upload; null before one. */
  targetVersion: z.string().nullable(),
  mrNumber: z.number().int().nullable(),
  mrUrl: z.string().nullable(),
  failure: z
    .object({
      code: z.string().meta({
        description:
          'For `failed` a failure code (manifest_unsupported, missing_tool, package_manager, verify_failed, unplanned_change, timeout, upload_refused, scm_permission, scm_refused, scm_unavailable, scm_not_bound, fixes_disabled), for `no_fix` its reason (no_fixed_version, declined, several_lines, not_installed, unresolvable)',
      }),
      /** A fixed text, or the package manager's scrubbed output (at most 2 KiB). */
      message: z.string(),
    })
    .nullable(),
  updatedAt: timestamp,
});
export type DependencyFix = z.infer<typeof dependencyFixSchema>;

/** spec §6.8: a fix as `GET /projects/{id}/fixes` lists it and a request answers it. */
export const fixListItemSchema = dependencyFixSchema.extend({
  family: z.enum(FIX_FAMILIES),
  packageName: z.string(),
  /** `auto` for a fix the automatic mode requested (spec §6.3). */
  origin: z.enum(['manual', 'auto']),
  /** The installed version the MR title names (R30); null before an upload. */
  installedVersion: z.string().nullable(),
  /** `qualor/fix/<family>/<package-slug>[-<n>]` (R32). */
  branch: z.string(),
  createdAt: timestamp,
});
export type FixListItem = z.infer<typeof fixListItemSchema>;

export function fixDto(row: DependencyFixRow): DependencyFix {
  return {
    id: row.id,
    state: row.state,
    refresh: row.refresh,
    targetVersion: row.targetVersion,
    mrNumber: row.mrNumber,
    mrUrl: row.mrUrl,
    failure: row.failure,
    updatedAt: iso(row.updatedAt),
  };
}

export function fixListItem(row: DependencyFixRow): FixListItem {
  return {
    ...fixDto(row),
    family: row.family,
    packageName: row.packageName,
    origin: row.origin,
    installedVersion: row.installedVersion,
    branch: row.branch,
    createdAt: iso(row.createdAt),
  };
}

/**
 * B7, ruling T8b: the package name a fix is stored and found under: a Python package's PEP 503 name
 * (lower case, each run of `-`, `_` and `.` one `-`), so `Django_Rest` and `django-rest` are one
 * fix; every other family's name exactly as Trivy reports it.
 */
export function fixPackageName(family: FixFamily, packageName: string): string {
  return family === 'python' ? normalizePythonName(packageName) : packageName;
}

const BRANCH_PREFIX = 'qualor/fix';
/** R32: the whole branch name, the `-<n>` suffix included. */
const MAX_BRANCH_CHARS = 100;
/** The slug of a name with no letter or digit left (ruling T5a). */
export const EMPTY_PACKAGE_SLUG = 'package';

/** Without leading and trailing `.` and `-`. */
function trimEdges(slug: string): string {
  const edge = (c: string | undefined) => c === '.' || c === '-';
  let start = 0;
  let end = slug.length;
  while (start < end && edge(slug[start])) start += 1;
  while (end > start && edge(slug[end - 1])) end -= 1;
  return slug.slice(start, end);
}

/**
 * Ruling T5a: a slug of `[a-z0-9._-]` that is one valid ref component (`git check-ref-format`):
 * no `..`, no leading `.`, no trailing `.` or `-`, no `.lock` ending; possibly empty.
 */
function tidySlug(slug: string): string {
  const trimmed = trimEdges(slug.replaceAll(/\.{2,}/g, '.'));
  return trimmed.endsWith('.lock') ? `${trimmed.slice(0, -'.lock'.length)}-lock` : trimmed;
}

/**
 * spec §6.7, R32: the package's slug in its fix branch: lowercase, every run of characters other
 * than `[a-z0-9._-]` one `-` (`@scope/name` → `scope-name`, `group:artifact` → `group-artifact`),
 * a valid ref component ({@link tidySlug}); {@link EMPTY_PACKAGE_SLUG} when nothing is left.
 */
export function packageSlug(name: string): string {
  const slug = tidySlug(name.toLowerCase().replaceAll(/[^a-z0-9._-]+/g, '-'));
  return slug === '' ? EMPTY_PACKAGE_SLUG : slug;
}

/**
 * R32: `qualor/fix/<family>/<package-slug>`, with `-<n>` for n of 2 and more, at most 100
 * characters: a long slug is cut (and tidied again), the suffix kept. Unique among a project's
 * fixes only through `uniqueBranch`.
 */
export function fixBranchName(family: FixFamily, packageName: string, n: number): string {
  if (!Number.isInteger(n) || n < 1) throw new RangeError(`A branch number is 1 or more: ${n}`);
  const prefix = `${BRANCH_PREFIX}/${family}/`;
  const suffix = n === 1 ? '' : `-${n}`;
  const room = MAX_BRANCH_CHARS - prefix.length - suffix.length;
  const slug = packageSlug(packageName);
  const fitted = slug.length <= room ? slug : tidySlug(slug.slice(0, room));
  return `${prefix}${fitted === '' ? EMPTY_PACKAGE_SLUG : fitted}${suffix}`;
}
