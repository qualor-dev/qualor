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

/** What the base allows a new entry: origins (Ruling T3f: of registry entries only) and pairs. */
interface BaseFacts {
  keyOf: TupleKey;
  origins: ReadonlySet<string>;
  /** The base's `(slot, name)` pairs: aliases (C1) and what Ruling T3n counts as known. */
  pairs: ReadonlySet<string>;
  /** {@link sourceOrigin} of an entry's source, once per distinct source. */
  originOf: (entry: LockEntry) => string | null;
  integrityRequired: boolean;
}

function originsBySource(): (entry: LockEntry) => string | null {
  const origins = new Map<string, string | null>();
  return ({ source }) => {
    if (source === null) return null;
    const known = origins.get(source);
    if (known !== undefined) return known;
    const origin = sourceOrigin(source);
    origins.set(source, origin);
    return origin;
  };
}

function baseFacts(base: readonly LockEntry[], ctx: LockCheckOptions, keyOf: TupleKey): BaseFacts {
  const originOf = originsBySource();
  const origins = new Set(ctx.publicHosts.map((host) => sourceOrigin(host) ?? host));
  for (const entry of base) {
    const origin = entry.kind === 'registry' ? originOf(entry) : null;
    if (origin !== null) origins.add(origin);
  }
  const pairs = new Set(base.map((entry) => pairOf(entry, keyOf)));
  return { keyOf, origins, pairs, originOf, integrityRequired: ctx.integrityRequired };
}

function newEntryRule(entry: LockEntry, facts: BaseFacts): FixRule | null {
  if (entry.kind !== 'registry') return 'source_kind';
  // Fix round 1, C1: another package in a slot only where the base had that alias.
  if (isAlias(entry) && !facts.pairs.has(pairOf(entry, facts.keyOf))) return 'source_kind';
  if (entry.source !== null) {
    // Ruling T3c: a source that gives no origin fails closed; the readers write null, not a
    // reference, for a registry entry the format names no URL for.
    const origin = facts.originOf(entry);
    if (origin === null || !facts.origins.has(origin)) return 'new_source';
  }
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
 * The names the base's entries depend on, per scope. Scopes that hold the same set of
 * dependencies arrays share one set (fix round 4, R4-1), so alias copies cost no copies.
 */
function baseDependencies(
  base: readonly LockEntry[],
  packageName: string,
  keyOf: TupleKey,
): Map<string, ReadonlySet<string>> {
  const arrays = new Map<string, Set<readonly string[]>>();
  for (const entry of base) {
    const key = dependencyScope(entry, packageName, keyOf);
    const list = arrays.get(key);
    if (list === undefined) arrays.set(key, new Set([entry.dependencies]));
    else list.add(entry.dependencies);
  }
  const setOf = perArraySet((lists): ReadonlySet<string> => new Set(lists.flat()));
  const allowed = new Map<string, ReadonlySet<string>>();
  for (const [key, lists] of arrays) allowed.set(key, setOf(lists));
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
 * covered here: new versions of the package (the residual T3i discloses) and brand-new pairs,
 * which have no base scope; Rulings T3m and T3n restrict how those are reached.
 */
function dependenciesWidened(
  base: readonly LockEntry[],
  next: readonly LockEntry[],
  packageName: string,
  keyOf: TupleKey,
): boolean {
  const allowed = baseDependencies(base, packageName, keyOf);
  const verdicts = new Map<ReadonlySet<string>, Map<readonly string[], boolean>>();
  return next.some((entry) => {
    const names = allowed.get(dependencyScope(entry, packageName, keyOf));
    return names !== undefined && widens(entry.dependencies, names, verdicts);
  });
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
 * The work is linear in the entries and their distinct dependencies arrays: every key is a tuple
 * of interned ids, and origins, allowed sets and verdicts are computed once per distinct source,
 * set of arrays and (set, array) pair. The readers bound the arrays' total length
 * (`FIX_LIMITS.lockDependencyRefs`, fix round 4).
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
  if (dependenciesWidened(base, next, ctx.packageName, keyOf)) {
    return fixRefused('other_change', ctx.lockfile);
  }
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
