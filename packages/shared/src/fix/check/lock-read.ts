/**
 * What the JS lockfile readers share: entries before their dependents are known, the bound on the
 * work of a read (fix round 4), source kinds and the registry tarball rule. A reader throws on a
 * file it cannot read; `checkJsLockfile` answers `unparsable` instead.
 */
import { FIX_LIMITS } from '../families';
import type { LockEntry, LockEntryKind } from './types';
import { isObject, own, parseUrl, perArraySet, tupleKeys, type JsonObject } from './values';

/** An entry before its dependents are known; `dependencies` are the slots it depends on. */
export type RawEntry = Omit<LockEntry, 'dependents'>;

/** A lockfile read: its format (manager and major version, fix round 1 C4) and its entries. */
export interface ReadLock {
  format: string;
  entries: LockEntry[];
}

export function unreadable(what: string): never {
  throw new Error(`unreadable lockfile at ${what.slice(0, 200)}`);
}

export function objectAt(value: unknown, what: string): JsonObject {
  if (!isObject(value)) unreadable(what);
  return value;
}

/** An object-valued section; an empty object when it is absent or null. */
export function sectionOf(object: JsonObject, key: string): JsonObject {
  const value = own(object, key);
  return value === undefined || value === null ? {} : objectAt(value, key);
}

/** The slot names of an entry's dependency maps (the given sections). */
export function dependencyNames(entry: unknown, sections: readonly string[]): string[] {
  if (!isObject(entry)) return [];
  return sections.flatMap((section) => {
    const deps = own(entry, section);
    return isObject(deps) ? Object.keys(deps) : [];
  });
}

/** The entry in a slot: an alias when the slot is not the package's own name. */
export function inSlot(entry: RawEntry, slot: string): RawEntry {
  return slot === entry.name ? entry : { ...entry, slot };
}

function sorted(names: Iterable<string>): string[] {
  return [...new Set(names)].sort((a, b) => a.localeCompare(b));
}

const LIMIT = FIX_LIMITS.lockDependencyRefs;

/**
 * Fix round 4 (R4-1, R4-4): a hard bound on the work of a read, whatever the input's shape,
 * checked before any structure per entry is built. The dependency names of all raw entries are
 * counted, alias copies included; above `FIX_LIMITS.lockDependencyRefs` the file is unreadable.
 * So is a source longer than `FIX_LIMITS.lockSourceChars`.
 */
function assertWithinLimits(raw: readonly RawEntry[]): void {
  let references = 0;
  for (const { dependencies, source } of raw) {
    references += dependencies.length;
    if (references > LIMIT) unreadable('dependencies (too many names)');
    if (source !== null && source.length > FIX_LIMITS.lockSourceChars) {
      unreadable(`a source of ${source.length} characters`);
    }
  }
}

/**
 * Fix round 5 (R5-2): counts the dependency names of the entries a reader makes, as it makes them,
 * so the read stops as soon as the count is over `FIX_LIMITS.lockDependencyRefs`, not after the
 * whole file has been walked.
 */
export function entryCounter(
  what: string,
): <T extends Pick<RawEntry, 'dependencies'>>(entry: T) => T {
  let used = 0;
  return <T extends Pick<RawEntry, 'dependencies'>>(entry: T): T => {
    used += entry.dependencies.length;
    if (used > LIMIT) unreadable(`${what} (too many dependency names)`);
    return entry;
  };
}

/** A package (an entry's identity without its slot): its name and its copies' raw arrays. */
interface PackageCopies {
  name: string;
  arrays: Set<readonly string[]>;
}

function addTo<K, V>(map: Map<K, Set<V>>, key: K, value: V): void {
  const set = map.get(key);
  if (set === undefined) map.set(key, new Set([value]));
  else set.add(value);
}

/**
 * Each package's dependencies, sorted: one array per distinct set of raw arrays, so packages that
 * hold the same raw arrays share one sorted array, whatever their names (fix round 4, R4-1). The
 * arrays' total length is checked before any is built (fix round 5, R5-1).
 */
function sortedDependencies(packages: ReadonlyMap<string, PackageCopies>): Map<string, string[]> {
  const groups = new Map<string, ReadonlySet<readonly string[]>>();
  for (const [key, { arrays }] of packages) groups.set(key, arrays);
  const sortedOf = perArraySet(groups, LIMIT, (arrays) => sorted(arrays.flat()));
  return sortedOf ?? unreadable('dependencies (too many names to sort)');
}

/**
 * Fix round 5 (R5-1): the names the merged entries end up with, each the union of its package's
 * copies, counted over all of them; above `FIX_LIMITS.lockDependencyRefs` the file is unreadable.
 */
function assertMergedWithinLimit(
  merged: Iterable<readonly [RawEntry, string]>,
  dependencies: ReadonlyMap<string, readonly string[]>,
): void {
  let names = 0;
  for (const [, packageKey] of merged) {
    names += dependencies.get(packageKey)?.length ?? 0;
    if (names > LIMIT) unreadable('dependencies (too many names after the merge)');
  }
}

/** For each slot, the name lists of the packages holding a raw array that lists the slot. */
function slotHolders(packages: Iterable<PackageCopies>): Map<string, Set<readonly string[]>> {
  const byArray = new Map<readonly string[], Set<string>>();
  for (const { name, arrays } of packages) {
    for (const array of arrays) addTo(byArray, array, name);
  }
  const bySlot = new Map<string, Set<readonly string[]>>();
  for (const [array, names] of byArray) {
    const holders = [...names];
    for (const slot of array) addTo(bySlot, slot, holders);
  }
  return bySlot;
}

/**
 * The sorted names of the packages depending on each slot (fix round 4, R4-1). Each distinct raw
 * array contributes once, to the slots it lists; slots that the same arrays list share one sorted
 * array of their holders' names. Their total length is checked before any is built (fix round 5).
 */
function dependentsBySlot(packages: Iterable<PackageCopies>): Map<string, string[]> {
  const dependents = perArraySet(slotHolders(packages), LIMIT, (lists) => sorted(lists.flat()));
  return dependents ?? unreadable('dependents (too many names)');
}

/**
 * Entries with one identity become one. Every copy of a package (its alias copies in other slots
 * included) gets the union of its copies' dependencies, as one sorted array; Ruling T3l compares
 * those, so a second copy cannot hide an added dependency. Each entry also gets the sorted names
 * of the packages that depend on its slot (its name when it has none), one array per slot.
 *
 * The work is bounded, whatever the shape (fix rounds 4 and 5):
 * - {@link assertWithinLimits} first: at most `FIX_LIMITS.lockDependencyRefs` dependency names
 *   over all raw entries, alias copies counted, and no source over `FIX_LIMITS.lockSourceChars`;
 * - the sorted unions and the dependents are built once per distinct set of arrays, and only
 *   after their total length is known to be within the same limit;
 * - {@link assertMergedWithinLimit}: the names the merged entries end up with, summed over all of
 *   them, are within the same limit, so whatever walks the entries' arrays afterwards walks at
 *   most that many names;
 * - keys are interned ids ({@link tupleKeys}), so no key copies a source or another string the
 *   copies share.
 *
 * The arrays are shared between entries: do not mutate them.
 */
export function withDependents(raw: readonly RawEntry[]): LockEntry[] {
  assertWithinLimits(raw);
  const keyOf = tupleKeys();
  const merged = new Map<string, [RawEntry, string]>();
  const packages = new Map<string, PackageCopies>();
  for (const entry of raw) {
    const { name, version, source, kind, integrity, dependencies } = entry;
    const packageKey = keyOf(name, version, source, kind, integrity);
    const copies = packages.get(packageKey);
    if (copies === undefined) packages.set(packageKey, { name, arrays: new Set([dependencies]) });
    else copies.arrays.add(dependencies);
    // A slot is each copy's own text in the lockfile, so the key may hold it: last, after a `|`
    // that ids never hold.
    const alias = entry.slot !== undefined && entry.slot !== name;
    const key = alias ? `${packageKey}|${entry.slot}` : packageKey;
    if (!merged.has(key)) merged.set(key, [entry, packageKey]);
  }
  const dependencies = sortedDependencies(packages);
  assertMergedWithinLimit(merged.values(), dependencies);
  const dependents = dependentsBySlot(packages.values());
  const none: string[] = [];
  return [...merged.values()].map(([entry, packageKey]) => ({
    ...entry,
    dependencies: dependencies.get(packageKey) ?? none,
    dependents: dependents.get(entry.slot ?? entry.name) ?? none,
  }));
}

/** `name@range`, the name possibly scoped; null without an `@` after the first character. */
export function splitDescriptor(text: string): { name: string; range: string } | null {
  const atSign = text.indexOf('@', 1);
  return atSign < 1 ? null : { name: text.slice(0, atSign), range: text.slice(atSign + 1) };
}

/** Spec and version prefixes that name a git, file or link source. */
const SPEC_KINDS: readonly (readonly [RegExp, LockEntryKind])[] = [
  [/^(?:git\+|git:|git@|ssh:|github:|gitlab:|bitbucket:|gist:)/i, 'git'],
  [/^file:/i, 'file'],
  [/^link:/i, 'link'],
];

/** An http(s) URL as the package managers parse it (Ruling T3c); null for anything else. */
function httpUrl(text: string): URL | null {
  const url = text.includes(':') ? parseUrl(text) : null;
  return url?.protocol === 'http:' || url?.protocol === 'https:' ? url : null;
}

/**
 * The kind a dependency spec or a version names: git, `file:`, `link:`, or `tarball` for an
 * http(s) URL; null for a registry spec (a version, range or tag).
 */
export function specKind(spec: string): LockEntryKind | null {
  const kind = SPEC_KINDS.find(([pattern]) => pattern.test(spec.trim()))?.[1];
  if (kind !== undefined) return kind;
  return httpUrl(spec) === null ? null : 'tarball';
}

/**
 * Where an npm registry serves a package's tarball, after any registry prefix (Ruling T3b):
 * `/<name>/-/<base>-<version>.tgz`, `<base>` the name without its scope, a scope's `/` also
 * written `%2f` or `%2F`.
 */
function tarballPaths(name: string, version: string): string[] {
  const slash = name.indexOf('/');
  const scoped = name.startsWith('@') && slash > 0;
  const base = scoped ? name.slice(slash + 1) : name;
  const tail = `/-/${base}-${version}.tgz`;
  if (!scoped) return [`/${name}${tail}`];
  const scope = name.slice(0, slash);
  return [`/${name}${tail}`, `/${scope}%2f${base}${tail}`, `/${scope}%2F${base}${tail}`];
}

/**
 * The kind of a URL source (npm and Yarn classic `resolved`, a Berry archive URL). An http(s) URL
 * is the registry tarball of the entry's own name and version only when its path ends with
 * {@link tarballPaths}; any other http(s) URL is a tarball dependency, so a source cannot fetch
 * another package (Ruling T3b, fix round 1 C2).
 */
export function resolvedKind(resolved: string, name: string, version: string): LockEntryKind {
  const url = httpUrl(resolved);
  if (url === null) return specKind(resolved) ?? 'other';
  const paths = version === '' ? [] : tarballPaths(name, version);
  return paths.some((path) => url.pathname.endsWith(path)) ? 'registry' : 'tarball';
}
