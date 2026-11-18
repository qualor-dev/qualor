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
  /**
   * Rulings T3e and T3m: a new entry must be reachable from the package through the entries'
   * forward `dependencies`. Off for a format without a dependency graph (go.sum).
   */
  reachableOnly: boolean;
}

/** The raw authority of a URL: after the scheme and any `/` or `\`, up to `/`, `?`, `#` or `\`. */
const RAW_AUTHORITY = /^[a-z][a-z0-9+.-]*:[/\\]*([^/?#\\]*)/i;

/** A host and port in plain ASCII: letters, digits, dots, dashes, colons and IPv6 brackets. */
const PLAIN_AUTHORITY = /^[A-Za-z0-9.:[\]-]+$/;

/**
 * `scheme://host[:port]` of a URL source, as the WHATWG URL parser reads it (so `https:\\evil`,
 * `https:/evil` and surrounding space are host `evil`): lower case, without a default port. Null
 * for a source that does not parse or has no host (`file:…`, `npm:1.2.3`), and (fix round 1, C3)
 * when the raw authority holds user info, a `%` escape or any other character: parsers disagree
 * on those (Yarn 1's `url.parse` reads `registry.yarnpkg.co%6D` as `registry.yarnpkg.co`).
 */
export function sourceOrigin(source: string): string | null {
  const raw = RAW_AUTHORITY.exec(source.trim())?.[1];
  if (raw === undefined || !PLAIN_AUTHORITY.test(raw)) return null;
  const url = parseUrl(source);
  if (url === null || url.host === '') return null;
  return `${url.protocol}//${url.host}`.toLowerCase();
}

/** The name an entry is installed and depended on as. */
function slotOf(entry: LockEntry): string {
  return entry.slot ?? entry.name;
}

/** An entry whose slot holds another package (an alias). */
function isAlias(entry: LockEntry): boolean {
  return slotOf(entry) !== entry.name;
}

function aliasKey(entry: LockEntry): string {
  return JSON.stringify([slotOf(entry), entry.name]);
}

/**
 * An entry is new when its `(slot, name, version, source, kind, integrity)` is not in the base
 * (Ruling T3b, fix round 1 C1), so a base entry whose kind, integrity or slot changed is checked
 * again.
 */
function entryKey(entry: LockEntry): string {
  return JSON.stringify([
    slotOf(entry),
    entry.name,
    entry.version,
    entry.source,
    entry.kind,
    entry.integrity,
  ]);
}

function originOf(entry: LockEntry): string | null {
  return entry.source === null ? null : sourceOrigin(entry.source);
}

/** What the base allows a new entry: origins (Ruling T3f: of registry entries only) and aliases. */
interface BaseFacts {
  origins: ReadonlySet<string>;
  aliases: ReadonlySet<string>;
  integrityRequired: boolean;
}

function baseFacts(base: readonly LockEntry[], ctx: LockCheckOptions): BaseFacts {
  const origins = new Set(ctx.publicHosts.map((host) => sourceOrigin(host) ?? host));
  for (const entry of base) {
    const origin = entry.kind === 'registry' ? originOf(entry) : null;
    if (origin !== null) origins.add(origin);
  }
  const aliases = new Set(base.filter(isAlias).map(aliasKey));
  return { origins, aliases, integrityRequired: ctx.integrityRequired };
}

function newEntryRule(entry: LockEntry, facts: BaseFacts): FixRule | null {
  if (entry.kind !== 'registry') return 'source_kind';
  // Fix round 1, C1: another package in a slot only where the base had that alias.
  if (isAlias(entry) && !facts.aliases.has(aliasKey(entry))) return 'source_kind';
  if (entry.source !== null) {
    // Ruling T3c: a source that gives no origin fails closed; the readers write null, not a
    // reference, for a registry entry the format names no URL for.
    const origin = originOf(entry);
    if (origin === null || !facts.origins.has(origin)) return 'new_source';
  }
  if (facts.integrityRequired && (entry.integrity ?? '') === '') return 'missing_integrity';
  return null;
}

function groupBy(
  entries: readonly LockEntry[],
  keyOf: (entry: LockEntry) => string,
): Map<string, LockEntry[]> {
  const groups = new Map<string, LockEntry[]>();
  for (const entry of entries) {
    const key = keyOf(entry);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [entry]);
    else group.push(entry);
  }
  return groups;
}

/** The slots and names of the base's entries: a name in neither is brand-new (Ruling T3m). */
function baseNames(base: readonly LockEntry[]): Set<string> {
  const names = new Set<string>();
  for (const entry of base) {
    names.add(entry.name);
    names.add(slotOf(entry));
  }
  return names;
}

/**
 * A walk over the forward dependencies. Each name is expanded once, each slot at most twice
 * (closed, then open), and each dependencies array at most once per mode, so the walk is linear
 * in the entries and their distinct arrays (fix rounds 2 and 3, N1 and NB1).
 */
interface Walk {
  packageName: string;
  known: ReadonlySet<string>;
  byName: ReadonlyMap<string, LockEntry[]>;
  bySlot: ReadonlyMap<string, LockEntry[]>;
  names: Set<string>;
  /** Slot → whether it was followed open (may reach brand-new names). */
  slots: Map<string, boolean>;
  walked: { open: Set<readonly string[]>; closed: Set<readonly string[]> };
  queue: string[];
}

function reachName(walk: Walk, name: string): void {
  if (walk.names.has(name)) return;
  walk.names.add(name);
  walk.queue.push(name);
}

/**
 * The names of the entries in a slot (an alias's slot holds another name). A closed edge reaches
 * only names the base has.
 */
function followSlot(walk: Walk, slot: string, open: boolean): void {
  const followed = walk.slots.get(slot);
  if (followed === true || (followed === false && !open)) return;
  walk.slots.set(slot, open);
  for (const entry of walk.bySlot.get(slot) ?? []) {
    if (open || walk.known.has(entry.name)) reachName(walk, entry.name);
  }
}

/**
 * Ruling T3m: the edges of the package's own entries, and of entries whose name is brand-new,
 * may reach brand-new names; edges of other entries reach only names the base has.
 */
function expandEntry(walk: Walk, entry: LockEntry): void {
  const open = isPackageEntry(entry, walk.packageName) || !walk.known.has(entry.name);
  const walked = open ? walk.walked.open : walk.walked.closed;
  if (walked.has(entry.dependencies)) return;
  walked.add(entry.dependencies);
  for (const slot of entry.dependencies) followSlot(walk, slot, open);
}

/**
 * Rulings T3e and T3m: the names reachable from the package. They are its name and the names
 * held in its slot, then, for every reachable name, the names in the slots its entries depend on;
 * a brand-new name (no base entry has it as slot or name) only through the package's own entries
 * or other brand-new names. Names the base has are reached through any entry, so a package that
 * moves to another folder is no new dependency.
 */
function reachableNames(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  packageName: string,
): Set<string> {
  const walk: Walk = {
    packageName,
    known: baseNames(base),
    byName: groupBy(next, (entry) => entry.name),
    bySlot: groupBy(next, slotOf),
    names: new Set(),
    slots: new Map(),
    walked: { open: new Set(), closed: new Set() },
    queue: [],
  };
  reachName(walk, packageName);
  followSlot(walk, packageName, true);
  for (let name = walk.queue.pop(); name !== undefined; name = walk.queue.pop()) {
    for (const entry of walk.byName.get(name) ?? []) expandEntry(walk, entry);
  }
  return walk.names;
}

/**
 * Ruling T3i: the entries of `next` that the base does not have (by identity: slot, name,
 * version, source, kind and integrity), in `next` order. The MR body lists them.
 */
export function newLockEntries(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
): LockEntry[] {
  const known = new Set(base.map(entryKey));
  return next.filter((entry) => !known.has(entryKey(entry)));
}

function isPackageEntry(entry: LockEntry, packageName: string): boolean {
  return entry.name === packageName || entry.slot === packageName;
}

/**
 * Where Ruling T3l compares an entry's dependencies: by (slot, name), and for an entry of the
 * package by (slot, name, version).
 */
function dependencyScope(entry: LockEntry, packageName: string): string {
  const scope = [slotOf(entry), entry.name];
  return JSON.stringify(isPackageEntry(entry, packageName) ? [...scope, entry.version] : scope);
}

/**
 * The names the base's entries depend on, per scope. A scope with one dependencies array (the
 * alias copies of a package share theirs) gets that array's set, shared between scopes, so alias
 * fan-out costs no copies (fix round 3, NB1).
 */
function baseDependencies(
  base: readonly LockEntry[],
  packageName: string,
): Map<string, ReadonlySet<string>> {
  const arrays = new Map<string, Set<readonly string[]>>();
  for (const entry of base) {
    const key = dependencyScope(entry, packageName);
    const list = arrays.get(key);
    if (list === undefined) arrays.set(key, new Set([entry.dependencies]));
    else list.add(entry.dependencies);
  }
  const sets = new Map<readonly string[], ReadonlySet<string>>();
  const allowed = new Map<string, ReadonlySet<string>>();
  for (const [key, lists] of arrays) {
    const [only] = lists;
    if (lists.size === 1 && only !== undefined) {
      const set = sets.get(only) ?? new Set(only);
      sets.set(only, set);
      allowed.set(key, set);
    } else {
      allowed.set(key, new Set([...lists].flat()));
    }
  }
  return allowed;
}

/** Whether `names` holds a name `allowed` lacks; each (set, array) pair is computed once. */
function widens(
  names: readonly string[],
  allowed: ReadonlySet<string>,
  verdicts: Map<ReadonlySet<string>, Map<readonly string[], boolean>>,
): boolean {
  const byArray = verdicts.get(allowed) ?? new Map<readonly string[], boolean>();
  verdicts.set(allowed, byArray);
  const known = byArray.get(names);
  if (known !== undefined) return known;
  const verdict = names.some((name) => !allowed.has(name));
  byArray.set(names, verdict);
  return verdict;
}

/**
 * Ruling T3l (refining T3j): a package the base has, by (slot, name), may depend only on names
 * some base entry of it depended on, whatever its new version, source or integrity; an existing
 * version of the package itself, by (slot, name, version), likewise. Fewer names are fine. Not
 * covered here: new versions of the package (the residual T3i discloses) and brand-new names,
 * which have no base scope; Ruling T3m restricts how those are reached.
 */
function dependenciesWidened(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  packageName: string,
): boolean {
  const allowed = baseDependencies(base, packageName);
  const verdicts = new Map<ReadonlySet<string>, Map<readonly string[], boolean>>();
  return next.some((entry) => {
    const names = allowed.get(dependencyScope(entry, packageName));
    return names !== undefined && widens(entry.dependencies, names, verdicts);
  });
}

/**
 * B1 for lockfiles. Every new entry is a registry entry (`source_kind`) and no alias the base did
 * not have (`source_kind`), whose source is null or a URL on an origin of the base's registry
 * entries or a public registry of the format (`new_source`), with an integrity hash where the
 * format has them (`missing_integrity`); the first failing new entry, in `next` order, names the
 * rule. Then no package the base has may depend on a name it did not (`other_change`, Ruling
 * T3l), and, with `reachableOnly`, every new entry must be reachable from the package
 * (`new_dependency`, Rulings T3e and T3m).
 */
export function checkLockEntries(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  ctx: FixCheckContext & LockCheckOptions,
): FixCheckResult {
  const added = newLockEntries(base, next);
  const facts = baseFacts(base, ctx);
  for (const entry of added) {
    const rule = newEntryRule(entry, facts);
    if (rule !== null) return fixRefused(rule, ctx.lockfile);
  }
  if (dependenciesWidened(base, next, ctx.packageName)) {
    return fixRefused('other_change', ctx.lockfile);
  }
  if (ctx.reachableOnly) {
    const reached = reachableNames(base, next, ctx.packageName);
    if (added.some((entry) => !reached.has(entry.name))) {
      return fixRefused('new_dependency', ctx.lockfile);
    }
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

/** The versions of the package, and of whatever its slot holds (fix round 1, C1). */
function packageVersions(entries: readonly LockEntry[], packageName: string): string[] {
  const own = entries.filter((e) => isPackageEntry(e, packageName));
  return [...new Set(own.map((e) => e.version))];
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
