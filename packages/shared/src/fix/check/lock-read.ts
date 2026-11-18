/**
 * What the JS lockfile readers share: entries before their dependents are known, dependency
 * edges, source kinds and the registry tarball rule. A reader throws on a file it cannot read;
 * `checkJsLockfile` answers `unparsable` instead.
 */
import type { LockEntry, LockEntryKind } from './types';
import { isObject, own, parseUrl, type JsonObject } from './values';

/** An entry before its dependents are known. */
export type RawEntry = Omit<LockEntry, 'dependents'>;

/** `from` (a package name) depends on each slot named in `to`. */
export interface Edge {
  from: string;
  to: readonly string[];
}

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

/**
 * Each entry gets the sorted names of the packages that depend on its slot (its name when it has
 * none); duplicate entries go.
 */
export function withDependents(raw: readonly RawEntry[], edges: readonly Edge[]): LockEntry[] {
  const dependents = new Map<string, Set<string>>();
  for (const { from, to } of edges) {
    for (const slot of to) {
      const names = dependents.get(slot) ?? new Set<string>();
      names.add(from);
      dependents.set(slot, names);
    }
  }
  const seen = new Set<string>();
  const entries: LockEntry[] = [];
  for (const entry of raw) {
    const { slot, name, version, source, kind, integrity } = entry;
    const key = JSON.stringify([slot, name, version, source, kind, integrity]);
    if (seen.has(key)) continue;
    seen.add(key);
    const names = [...(dependents.get(slot ?? name) ?? [])].sort((a, b) => a.localeCompare(b));
    entries.push({ ...entry, dependents: names });
  }
  return entries;
}

/** `name@range`, the name possibly scoped; null without an `@` after the first character. */
export function splitDescriptor(text: string): { name: string; range: string } | null {
  const atSign = text.indexOf('@', 1);
  return atSign < 1 ? null : { name: text.slice(0, atSign), range: text.slice(atSign + 1) };
}

/** A package name, scoped or not. */
export const PACKAGE_NAME = /^(?:@[\w.~-]+\/)?[\w.~-]+$/;

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
