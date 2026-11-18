/**
 * Lockfile entries (spec §12 B1, B3): what a fix may add to a lockfile, whatever its format, and
 * whether the package still resolves below its targets.
 */
import {
  compareVersions,
  releaseLine,
  schemeOf,
  versionParses,
  type VersionScheme,
} from '../versions';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixRule,
  type FixTarget,
  type LockEntry,
} from './types';
import { parseUrl } from './values';

/** What a lockfile check adds to the fix: the file, the format's public registries and hashes. */
export interface LockCheckOptions {
  lockfile: string;
  /** Origins (`scheme://host`) every lockfile of the format may use. */
  publicHosts: readonly string[];
  /** Whether a new entry needs an integrity hash (the format has them). */
  integrityRequired: boolean;
}

/**
 * `scheme://host[:port]` of a URL source, as the WHATWG URL parser reads it (so `https:\\evil`,
 * `https:/evil` and surrounding space are host `evil`): lower case, without user info, without a
 * default port. Null for a source that does not parse or has no host (`file:…`, `npm:1.2.3`).
 */
export function sourceOrigin(source: string): string | null {
  const url = parseUrl(source);
  if (url === null || url.host === '') return null;
  return `${url.protocol}//${url.host}`.toLowerCase();
}

/**
 * An entry is new when its `(name, version, source, kind, integrity)` is not in the base (Ruling
 * T3b), so a base entry whose kind or integrity changed is checked again.
 */
function entryKey(entry: LockEntry): string {
  return JSON.stringify([entry.name, entry.version, entry.source, entry.kind, entry.integrity]);
}

function originOf(entry: LockEntry): string | null {
  return entry.source === null ? null : sourceOrigin(entry.source);
}

function newEntryRule(
  entry: LockEntry,
  origins: ReadonlySet<string>,
  integrityRequired: boolean,
): FixRule | null {
  if (entry.kind !== 'registry') return 'source_kind';
  if (entry.source !== null) {
    // Ruling T3c: a source that gives no origin fails closed; the readers write null, not a
    // reference, for a registry entry the format names no URL for.
    const origin = originOf(entry);
    if (origin === null || !origins.has(origin)) return 'new_source';
  }
  if (integrityRequired && (entry.integrity ?? '') === '') return 'missing_integrity';
  return null;
}

/**
 * B1 for lockfiles: every new entry is a registry entry (`source_kind`) whose source is null or a
 * URL on an origin the base lockfile or a public registry of the format uses (`new_source`), with
 * an integrity hash where the format has them (`missing_integrity`). The first failing new entry,
 * in `next` order, names the rule.
 */
export function checkLockEntries(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  ctx: FixCheckContext & LockCheckOptions,
): FixCheckResult {
  const known = new Set(base.map(entryKey));
  const origins = new Set(ctx.publicHosts.map((host) => sourceOrigin(host) ?? host));
  for (const entry of base) {
    const origin = originOf(entry);
    if (origin !== null) origins.add(origin);
  }
  for (const entry of next) {
    if (known.has(entryKey(entry))) continue;
    const rule = newEntryRule(entry, origins, ctx.integrityRequired);
    if (rule !== null) return fixRefused(rule, ctx.lockfile);
  }
  return FIX_CHECK_OK;
}

/** The smallest target that parses; null when none does. */
function smallestTarget(targets: readonly FixTarget[], scheme: VersionScheme): string | null {
  let smallest: string | null = null;
  for (const { target } of targets) {
    if (!versionParses(scheme, target)) continue;
    if (smallest === null || (compareVersions(scheme, target, smallest) ?? 0) < 0)
      smallest = target;
  }
  return smallest;
}

/** Whether `installed ≤ v < target` for some target. */
function stillVulnerable(v: string, targets: readonly FixTarget[], scheme: VersionScheme): boolean {
  return targets.some(
    ({ installed, target }) =>
      (compareVersions(scheme, installed, v) ?? 1) <= 0 &&
      (compareVersions(scheme, v, target) ?? 0) < 0,
  );
}

/** Whether `v < target` for a target on `v`'s own release line (Ruling T3a). */
function belowLineTarget(v: string, targets: readonly FixTarget[], scheme: VersionScheme): boolean {
  const line = releaseLine(scheme, v);
  return (
    line !== null &&
    targets.some(
      ({ target }) =>
        releaseLine(scheme, target) === line && (compareVersions(scheme, v, target) ?? 0) < 0,
    )
  );
}

/**
 * A new version lies below the smallest target or below the target of its own line, or cannot be
 * compared with the smallest target (fail closed).
 */
function newBelow(
  v: string,
  smallest: string | null,
  targets: readonly FixTarget[],
  scheme: VersionScheme,
): boolean {
  const c = smallest === null ? null : compareVersions(scheme, v, smallest);
  return c === null || c < 0 || belowLineTarget(v, targets, scheme);
}

/**
 * B3, §12 B1: whether the package's resolved versions still miss a target: some `v` has
 * `installed ≤ v < target` for a target, or a new version (one `baseVersions` lacks) lies below the
 * smallest target or below the target of its own release line (Ruling T3a). Without
 * `baseVersions` every version counts as new.
 */
export function belowTarget(
  versions: readonly string[],
  targets: readonly FixTarget[],
  scheme: VersionScheme,
  baseVersions: readonly string[] = [],
): boolean {
  if (targets.length === 0) return false;
  const old = new Set(baseVersions);
  const smallest = smallestTarget(targets, scheme);
  return versions.some(
    (v) =>
      stillVulnerable(v, targets, scheme) ||
      (!old.has(v) && newBelow(v, smallest, targets, scheme)),
  );
}

function packageVersions(entries: readonly LockEntry[], packageName: string): string[] {
  return [...new Set(entries.filter((e) => e.name === packageName).map((e) => e.version))];
}

/**
 * {@link belowTarget} over the package's versions in one lockfile. Ruling F14: only the targets of
 * that lockfile apply, and a lockfile without any is not checked.
 */
export function lockfileBelowTarget(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  ctx: FixCheckContext,
  lockfile: string,
): boolean {
  const targets = ctx.targets.filter((t) => t.lockfile === lockfile);
  if (targets.length === 0) return false;
  return belowTarget(
    packageVersions(next, ctx.packageName),
    targets,
    schemeOf(ctx.family),
    packageVersions(base, ctx.packageName),
  );
}
