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
    if (references > FIX_LIMITS.lockDependencyRefs) unreadable('dependencies (too many names)');
    if (source !== null && source.length > FIX_LIMITS.lockSourceChars) {
      unreadable(`a source of ${source.length} characters`);
    }
  }
}

/** A package (an entry's identity without its slot): its name and its copies' raw arrays. */
interface PackageCopies {
  name: string;
  arrays: Set<readonly string[]>;
}

function addTo<K>(map: Map<K, Set<string>>, key: K, value: string): void {
  const set = map.get(key);
  if (set === undefined) map.set(key, new Set([value]));
  else set.add(value);
}

/**
 * Each package's dependencies, sorted: one array per distinct set of raw arrays, so packages that
 * hold the same raw arrays share one sorted array, whatever their names (fix round 4, R4-1).
 */
function sortedDependencies(packages: ReadonlyMap<string, PackageCopies>): Map<string, string[]> {
  const sortedOf = perArraySet((arrays) => sorted(arrays.flat()));
  const result = new Map<string, string[]>();
  for (const [key, { arrays }] of packages) result.set(key, sortedOf(arrays));
  return result;
}

/** For each raw array, the names of the packages holding it; and for each slot, those arrays. */
function slotHolders(packages: Iterable<PackageCopies>): {
  holders: Set<string>[];
  bySlot: Map<string, number[]>;
} {
  const byArray = new Map<readonly string[], Set<string>>();
  for (const { name, arrays } of packages) {
    for (const array of arrays) addTo(byArray, array, name);
  }
  const holders: Set<string>[] = [];
  const bySlot = new Map<string, number[]>();
  for (const [array, names] of byArray) {
    const id = holders.push(names) - 1;
    for (const slot of array) {
      const ids = bySlot.get(slot);
      if (ids === undefined) bySlot.set(slot, [id]);
      else if (ids.at(-1) !== id) ids.push(id);
    }
  }
  return { holders, bySlot };
}

/**
 * The sorted names of the packages depending on each slot (fix round 4, R4-1). Each distinct raw
 * array contributes once, to the slots it lists; slots that the same arrays list share one sorted
 * array of their holders' names.
 */
function dependentsBySlot(packages: Iterable<PackageCopies>): Map<string, string[]> {
  const { holders, bySlot } = slotHolders(packages);
  const bySet = new Map<string, string[]>();
  const dependents = new Map<string, string[]>();
  for (const [slot, ids] of bySlot) {
    const key = ids.join(',');
    const names = bySet.get(key) ?? sorted(ids.flatMap((id) => [...(holders[id] ?? [])]));
    bySet.set(key, names);
    dependents.set(slot, names);
  }
  return dependents;
}

/**
 * Entries with one identity become one. Every copy of a package (its alias copies in other slots
 * included) gets the union of its copies' dependencies, as one sorted array; Ruling T3l compares
 * those, so a second copy cannot hide an added dependency. Each entry also gets the sorted names
 * of the packages that depend on its slot (its name when it has none), one array per slot.
 *
 * The work is bounded, whatever the shape (fix round 4, R4-1 and R4-4):
 * - {@link assertWithinLimits} first: at most `FIX_LIMITS.lockDependencyRefs` dependency names
 *   over all raw entries, alias copies counted, and no source over `FIX_LIMITS.lockSourceChars`;
 * - packages that hold the same raw arrays, whatever their names, share one sorted dependencies
 *   array, and each raw array contributes once to the dependents of the slots it lists;
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
