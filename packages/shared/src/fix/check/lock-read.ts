/**
 * What the JS lockfile readers share: entries before their dependents are known, source kinds
 * and the registry tarball rule. A reader throws on a file it cannot read; `checkJsLockfile`
 * answers `unparsable` instead.
 */
import type { LockEntry, LockEntryKind } from './types';
import { isObject, own, parseUrl, type JsonObject } from './values';

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

/** The identity `checkLockEntries` compares entries by. */
function identityOf({ slot, name, version, source, kind, integrity }: RawEntry): string {
  return JSON.stringify([slot, name, version, source, kind, integrity]);
}

/** A package's identity without its slot: the alias copies of one package share it. */
function packageKeyOf({ name, version, source, kind, integrity }: RawEntry): string {
  return JSON.stringify([name, version, source, kind, integrity]);
}

/** The union of a package's dependencies, each dependencies array read once. */
interface PackageDependencies {
  name: string;
  names: Set<string>;
  arrays: Set<readonly string[]>;
}

function mergeDependencies(packages: Map<string, PackageDependencies>, entry: RawEntry): string {
  const key = packageKeyOf(entry);
  let known = packages.get(key);
  if (known === undefined) {
    known = { name: entry.name, names: new Set(), arrays: new Set() };
    packages.set(key, known);
  }
  // Fix round 3, NB1: alias copies share one array, which is read once, not once per copy.
  if (!known.arrays.has(entry.dependencies)) {
    known.arrays.add(entry.dependencies);
    for (const name of entry.dependencies) known.names.add(name);
  }
  return key;
}

/** Each package's sorted dependencies, and the names of the packages depending on each slot. */
function indexPackages(packages: ReadonlyMap<string, PackageDependencies>): {
  dependencies: Map<string, string[]>;
  dependents: Map<string, Set<string>>;
} {
  const dependencies = new Map<string, string[]>();
  const dependents = new Map<string, Set<string>>();
  for (const [key, { name, names }] of packages) {
    dependencies.set(key, sorted(names));
    for (const slot of names) {
      const set = dependents.get(slot);
      if (set === undefined) dependents.set(slot, new Set([name]));
      else set.add(name);
    }
  }
  return { dependencies, dependents };
}

/**
 * Entries with one identity become one. Every copy of a package (its alias copies in other slots
 * included) gets the union of its copies' dependencies, as one sorted array shared by them all;
 * Ruling T3l compares those, so a second copy cannot hide an added dependency. Each entry also
 * gets the sorted names of the packages that depend on its slot (its name when it has none), one
 * array per slot, shared too. Each dependencies array is read once, so the work stays linear in
 * the input (fix rounds 2 and 3, N1 and NB1). Do not mutate the shared arrays.
 */
export function withDependents(raw: readonly RawEntry[]): LockEntry[] {
  const merged = new Map<string, [RawEntry, string]>();
  const packages = new Map<string, PackageDependencies>();
  for (const entry of raw) {
    const packageKey = mergeDependencies(packages, entry);
    const key = identityOf(entry);
    if (!merged.has(key)) merged.set(key, [entry, packageKey]);
  }
  const { dependencies, dependents } = indexPackages(packages);
  const shared = new Map<string, string[]>();
  return [...merged.values()].map(([entry, packageKey]) => {
    const slot = entry.slot ?? entry.name;
    const names = shared.get(slot) ?? sorted(dependents.get(slot) ?? []);
    shared.set(slot, names);
    return { ...entry, dependencies: dependencies.get(packageKey) ?? [], dependents: names };
  });
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
