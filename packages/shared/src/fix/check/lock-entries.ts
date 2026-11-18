/**
 * Lockfile entries (spec §12 B1, B3): what a fix may add to a lockfile, whatever its format, and
 * whether the package still resolves below its targets.
 */
import { FIX_LIMITS } from '../families';
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
import { parseUrl, perArraySet, tupleKeys, type TupleKey } from './values';

/** What a lockfile check adds to the fix: the file, the format's public registries and hashes. */
export interface LockCheckOptions {
  lockfile: string;
  /** Origins (`scheme://host`) every lockfile of the format may use. */
  publicHosts: readonly string[];
  /** Whether a new entry needs an integrity hash (the format has them). */
  integrityRequired: boolean;
  /**
   * Rulings T3e, T3m and T3n: a new entry's `(slot, name)` pair must be reachable from the
   * package through the entries' forward `dependencies`. Off for a format without a dependency
   * graph (go.sum).
   */
  reachableOnly: boolean;
  /**
   * The origin key of a registry entry's URL source; {@link sourceOrigin} unless set. Poetry sets
   * it so a legacy source is keyed by its `(url, reference)` pair (task 4 fix round 1, I2).
   */
  originOf?: (source: string) => string | null;
}

/**
 * Ruling T4f: the origin key of a registry entry without a URL source (pnpm integrity-only, Berry
 * `npm:`, Poetry without `[package.source]`): the format's default registry.
 */
export const DEFAULT_ORIGIN = 'default';

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

/**
 * A key of an entry's fields (fix round 4, R4-4): their interned ids, so no key copies a string
 * that copies of an entry share, such as its source. Only an alias's slot is written out, last
 * and after a `|` that ids never hold: it is each copy's own text in the lockfile (its folder,
 * pattern, descriptor or reference), and may hold any character.
 */
function keyWithSlot(entry: LockEntry, keyOf: TupleKey, ...parts: (string | null)[]): string {
  const key = keyOf(...parts);
  return isAlias(entry) ? `${key}|${entry.slot}` : key;
}

/** An entry's `(slot, name)` pair key (fix round 1 C1, Ruling T3n). */
function pairOf(entry: LockEntry, keyOf: TupleKey): string {
  return keyWithSlot(entry, keyOf, entry.name);
}

/**
 * An entry is new when its `(slot, name, version, source, kind, integrity)` is not in the base
 * (Ruling T3b, fix round 1 C1), so a base entry whose kind, integrity or slot changed is checked
 * again.
 */
function entryKey(entry: LockEntry, keyOf: TupleKey): string {
  const { name, version, source, kind, integrity } = entry;
  return keyWithSlot(entry, keyOf, name, version, source, kind, integrity);
}

/** Ruling T4f: the origin keys a package name's registry entries in the base came from. */
interface NameOrigins {
  keys: Set<string>;
  /** Whether one of them is a public registry (then every public registry may serve it). */
  public: boolean;
}

/** What the base allows a new entry: origins (Ruling T3f: of registry entries only) and pairs. */
interface BaseFacts {
  keyOf: TupleKey;
  origins: ReadonlySet<string>;
  publicOrigins: ReadonlySet<string>;
  /** Ruling T4f: the origin keys of the base's registry entries, per package name. */
  byName: ReadonlyMap<string, NameOrigins>;
  /** The base's `(slot, name)` pairs: aliases (C1) and what Ruling T3n counts as known. */
  pairs: ReadonlySet<string>;
  /** The origin key of an entry's URL source, once per distinct source. */
  originOf: (entry: LockEntry) => string | null;
  integrityRequired: boolean;
}

function originsBySource(origin: (source: string) => string | null) {
  const origins = new Map<string, string | null>();
  return ({ source }: LockEntry): string | null => {
    if (source === null) return null;
    const known = origins.get(source);
    if (known !== undefined) return known;
    const key = origin(source);
    origins.set(source, key);
    return key;
  };
}

/** A registry entry's origin key: {@link DEFAULT_ORIGIN} without a URL source. */
function registryKey(entry: LockEntry, originOf: BaseFacts['originOf']): string | null {
  return entry.source === null ? DEFAULT_ORIGIN : originOf(entry);
}

function addOrigin(byName: Map<string, NameOrigins>, name: string, key: string, open: boolean) {
  const known = byName.get(name);
  if (known === undefined) byName.set(name, { keys: new Set([key]), public: open });
  else {
    known.keys.add(key);
    known.public ||= open;
  }
}

function baseFacts(base: readonly LockEntry[], ctx: LockCheckOptions, keyOf: TupleKey): BaseFacts {
  const originOf = originsBySource(ctx.originOf ?? sourceOrigin);
  const publicOrigins = new Set(ctx.publicHosts.map((host) => sourceOrigin(host) ?? host));
  const origins = new Set(publicOrigins);
  const byName = new Map<string, NameOrigins>();
  for (const entry of base) {
    const key = entry.kind === 'registry' ? registryKey(entry, originOf) : null;
    if (key === null) continue;
    if (key !== DEFAULT_ORIGIN) origins.add(key);
    addOrigin(byName, entry.name, key, publicOrigins.has(key));
  }
  const pairs = new Set(base.map((entry) => pairOf(entry, keyOf)));
  const integrityRequired = ctx.integrityRequired;
  return { keyOf, origins, publicOrigins, byName, pairs, originOf, integrityRequired };
}

/**
 * Ruling T4f: a name the base has registry entries of keeps an origin key those entries used, or
 * moves between public registries when one of them was public. So a package of a private
 * registry or index cannot be fetched from a public one (dependency confusion), nor from the
 * default registry; a brand-new name is not bound.
 */
function keepsRegistry(entry: LockEntry, key: string, facts: BaseFacts): boolean {
  const known = facts.byName.get(entry.name);
  if (known === undefined || known.keys.has(key)) return true;
  return known.public && facts.publicOrigins.has(key);
}

function newEntryRule(entry: LockEntry, facts: BaseFacts): FixRule | null {
  if (entry.kind !== 'registry') return 'source_kind';
  // Fix round 1, C1: another package in a slot only where the base had that alias.
  if (isAlias(entry) && !facts.pairs.has(pairOf(entry, facts.keyOf))) return 'source_kind';
  // Ruling T3c: a source that gives no origin fails closed; the readers write null, not a
  // reference, for a registry entry the format names no URL for.
  const key = registryKey(entry, facts.originOf);
  if (key === null) return 'new_source';
  if (key !== DEFAULT_ORIGIN && !facts.origins.has(key)) return 'new_source';
  if (!keepsRegistry(entry, key, facts)) return 'new_source';
  if (facts.integrityRequired && (entry.integrity ?? '') === '') return 'missing_integrity';
  return null;
}

/**
 * A walk over the forward dependencies, by `(slot, name)` pair. Each entry's pair is computed
 * once, each pair expanded once, each slot followed at most twice (closed, then open), and each
 * dependencies array walked at most once per mode, so the walk is linear in the entries and their
 * distinct arrays (fix rounds 2 and 3, N1 and NB1).
 */
interface Walk {
  packageName: string;
  /** The base's pairs: an entry with another pair is brand-new (Ruling T3n). */
  known: ReadonlySet<string>;
  byPair: ReadonlyMap<string, LockEntry[]>;
  /** The distinct pairs of the entries in each slot (an alias's slot holds another name). */
  slotPairs: ReadonlyMap<string, ReadonlySet<string>>;
  pairs: Set<string>;
  /** Slot → whether it was followed open (may reach brand-new pairs). */
  slots: Map<string, boolean>;
  walked: { open: Set<readonly string[]>; closed: Set<readonly string[]> };
  queue: string[];
}

function reachPair(walk: Walk, pair: string): void {
  if (walk.pairs.has(pair)) return;
  walk.pairs.add(pair);
  walk.queue.push(pair);
}

/** The pairs in a slot. A closed edge reaches only pairs the base has. */
function followSlot(walk: Walk, slot: string, open: boolean): void {
  const followed = walk.slots.get(slot);
  if (followed === true || (followed === false && !open)) return;
  walk.slots.set(slot, open);
  for (const pair of walk.slotPairs.get(slot) ?? []) {
    if (open || walk.known.has(pair)) reachPair(walk, pair);
  }
}

/**
 * Rulings T3m and T3n: the edges of the package's own entries, and of brand-new entries (whose
 * pair the base lacks), may reach brand-new pairs; edges of other entries reach only pairs the
 * base has.
 */
function expandEntry(walk: Walk, entry: LockEntry, pair: string): void {
  const open = isPackageEntry(entry, walk.packageName) || !walk.known.has(pair);
  const walked = open ? walk.walked.open : walk.walked.closed;
  if (walked.has(entry.dependencies)) return;
  walked.add(entry.dependencies);
  for (const slot of entry.dependencies) followSlot(walk, slot, open);
}

/** The walk over `next`, each entry's pair computed once; the package's pairs are reached. */
function startWalk(next: readonly LockEntry[], packageName: string, facts: BaseFacts): Walk {
  const byPair = new Map<string, LockEntry[]>();
  const slotPairs = new Map<string, Set<string>>();
  const start: string[] = [];
  for (const entry of next) {
    const pair = pairOf(entry, facts.keyOf);
    const group = byPair.get(pair);
    if (group === undefined) byPair.set(pair, [entry]);
    else group.push(entry);
    const inSlot = slotPairs.get(slotOf(entry));
    if (inSlot === undefined) slotPairs.set(slotOf(entry), new Set([pair]));
    else inSlot.add(pair);
    if (isPackageEntry(entry, packageName)) start.push(pair);
  }
  const walk: Walk = {
    packageName,
    known: facts.pairs,
    byPair,
    slotPairs,
    pairs: new Set(),
    slots: new Map(),
    walked: { open: new Set(), closed: new Set() },
    queue: [],
  };
  for (const pair of start) reachPair(walk, pair);
  return walk;
}

/**
 * Rulings T3e, T3m and T3n: the `(slot, name)` pairs reachable from the package. They are the
 * pairs of the package's entries (its name, or its slot), then, for every reachable pair, the
 * pairs in the slots its entries depend on. A pair the base lacks (brand-new, even when its slot
 * or its name is in the base, as an alias slot is) is reached only through the package's own
 * entries or other brand-new ones. A pair the base has is reached through any entry, so a
 * package that moves to another folder (npm keeps the pair) is no new dependency.
 */
function reachablePairs(
  next: readonly LockEntry[],
  packageName: string,
  facts: BaseFacts,
): Set<string> {
  const walk = startWalk(next, packageName, facts);
  for (let pair = walk.queue.pop(); pair !== undefined; pair = walk.queue.pop()) {
    for (const entry of walk.byPair.get(pair) ?? []) expandEntry(walk, entry, pair);
  }
  return walk.pairs;
}

function addedEntries(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  keyOf: TupleKey,
): LockEntry[] {
  const known = new Set(base.map((entry) => entryKey(entry, keyOf)));
  return next.filter((entry) => !known.has(entryKey(entry, keyOf)));
}

/**
 * Ruling T3i: the entries of `next` that the base does not have (by identity: slot, name,
 * version, source, kind and integrity), in `next` order. The MR body lists them.
 */
export function newLockEntries(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
): LockEntry[] {
  return addedEntries(base, next, tupleKeys());
}

function isPackageEntry(entry: LockEntry, packageName: string): boolean {
  return entry.name === packageName || entry.slot === packageName;
}

/**
 * Where Ruling T3l compares an entry's dependencies: by (slot, name), and for an entry of the
 * package by (slot, name, version).
 */
function dependencyScope(entry: LockEntry, packageName: string, keyOf: TupleKey): string {
  return isPackageEntry(entry, packageName)
    ? keyWithSlot(entry, keyOf, entry.name, entry.version)
    : pairOf(entry, keyOf);
}

/**
 * The names the base's entries depend on, per scope: one set per distinct set of dependencies
 * arrays, shared by the scopes that hold it (fix round 4, R4-1). Scopes whose sets of arrays
 * differ each get their own set. Fix round 5 (R5-1): the sets' total size is summed before any is
 * built, and above `FIX_LIMITS.lockDependencyRefs` the answer is null (`unparsable`).
 */
function baseDependencies(
  base: readonly LockEntry[],
  packageName: string,
  keyOf: TupleKey,
): Map<string, ReadonlySet<string>> | null {
  const arrays = new Map<string, Set<readonly string[]>>();
  for (const entry of base) {
    const key = dependencyScope(entry, packageName, keyOf);
    const list = arrays.get(key);
    if (list === undefined) arrays.set(key, new Set([entry.dependencies]));
    else list.add(entry.dependencies);
  }
  const build = (lists: readonly (readonly string[])[]): ReadonlySet<string> =>
    new Set(lists.flat());
  return perArraySet(arrays, FIX_LIMITS.lockDependencyRefs, build);
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
 * covered here: new versions of the package (the residual T3i discloses) and brand-new pairs,
 * which have no base scope; Rulings T3m and T3n restrict how those are reached. `unparsable` when
 * the base's allowed sets would be too large to build (fix round 5, R5-1).
 */
function dependenciesRule(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  packageName: string,
  keyOf: TupleKey,
): FixRule | null {
  const allowed = baseDependencies(base, packageName, keyOf);
  if (allowed === null) return 'unparsable';
  const verdicts = new Map<ReadonlySet<string>, Map<readonly string[], boolean>>();
  const widened = next.some((entry) => {
    const names = allowed.get(dependencyScope(entry, packageName, keyOf));
    return names !== undefined && widens(entry.dependencies, names, verdicts);
  });
  return widened ? 'other_change' : null;
}

/**
 * B1 for lockfiles. Every new entry is a registry entry (`source_kind`) and no alias the base did
 * not have (`source_kind`), whose source is null or a URL on an origin of the base's registry
 * entries or a public registry of the format (`new_source`), with an integrity hash where the
 * format has them (`missing_integrity`); the first failing new entry, in `next` order, names the
 * rule. Then no package the base has may depend on a name it did not (`other_change`, Ruling
 * T3l), and, with `reachableOnly`, every new entry's `(slot, name)` pair must be reachable from
 * the package (`new_dependency`, Rulings T3e, T3m and T3n).
 *
 * The work is linear in the entries and in the total length of their dependencies arrays, which
 * the readers hold to `FIX_LIMITS.lockDependencyRefs` after the merge (fix rounds 4 and 5): every
 * key is a tuple of interned ids; origins and verdicts are computed once per distinct source and
 * (set, array) pair; the allowed sets are built once per distinct set of arrays, and only when
 * their total size is within the same limit, else the answer is `unparsable` (fix round 5).
 */
export function checkLockEntries(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  ctx: FixCheckContext & LockCheckOptions,
): FixCheckResult {
  const keyOf = tupleKeys();
  const added = addedEntries(base, next, keyOf);
  const facts = baseFacts(base, ctx, keyOf);
  for (const entry of added) {
    const rule = newEntryRule(entry, facts);
    if (rule !== null) return fixRefused(rule, ctx.lockfile);
  }
  const dependencies = dependenciesRule(base, next, ctx.packageName, keyOf);
  if (dependencies !== null) return fixRefused(dependencies, ctx.lockfile);
  if (ctx.reachableOnly) {
    const reached = reachablePairs(next, ctx.packageName, facts);
    if (added.some((entry) => !reached.has(pairOf(entry, keyOf)))) {
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
