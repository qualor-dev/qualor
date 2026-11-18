/**
 * npm lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, v1 to v3) as {@link LockEntry}
 * lists. A `node_modules/<slot>` folder (or a v1 key) is the slot; the package it holds is its
 * `name` field or the target of a v1 `npm:<name>@<version>` alias (fix round 1, C1).
 */
import {
  dependencyNames,
  inSlot,
  objectAt,
  resolvedKind,
  sectionOf,
  specKind,
  splitDescriptor,
  withDependents,
  type RawEntry,
  type ReadLock,
} from './lock-read';
import type { LockEntry } from './types';
import { isObject, own, str, stripBom, type JsonObject } from './values';

const NODE_MODULES = 'node_modules/';

/** The dependency maps of a v2/v3 entry (Rulings T3e and T3j follow them all). */
const PACKAGE_EDGES = ['dependencies', 'optionalDependencies', 'peerDependencies'];

/** v1's `requires` lists every dependency, optional ones included. */
const V1_EDGES = ['requires'];

interface NpmPackage {
  name: string;
  version: string;
}

/**
 * The package an npm entry holds: the target of a v1 `npm:<name>@<version>` alias, else the
 * entry's `name` field (a v2/v3 alias), else the slot's name, with the entry's version.
 */
function npmPackage(slot: string, entry: JsonObject): NpmPackage {
  const version = str(own(entry, 'version')) ?? '';
  const alias = version.startsWith('npm:') ? splitDescriptor(version.slice('npm:'.length)) : null;
  if (alias !== null) return { name: alias.name, version: alias.range };
  return { name: str(own(entry, 'name')) ?? slot, version };
}

/** The kind and source of an npm entry: `link`, a URL or `file:` version, or its `resolved`. */
function npmSource(
  key: string,
  entry: JsonObject,
  { name, version }: NpmPackage,
): Pick<RawEntry, 'kind' | 'source'> {
  const resolved = str(own(entry, 'resolved'));
  if (own(entry, 'link') === true) return { kind: 'link', source: resolved };
  const versionKind = specKind(version);
  if (versionKind !== null) return { kind: versionKind, source: resolved ?? version };
  if (resolved !== null) return { kind: resolvedKind(resolved, name, version), source: resolved };
  return { kind: key.includes(NODE_MODULES) ? 'registry' : 'path', source: null };
}

/**
 * An entry at `key`, depending on the slots of its dependency maps; `slot` is null for a key
 * outside `node_modules` (a workspace folder).
 */
function npmEntry(
  key: string,
  slot: string | null,
  entry: JsonObject,
  edges: readonly string[],
): RawEntry {
  const pkg = npmPackage(slot ?? key, entry);
  const raw = {
    ...pkg,
    ...npmSource(key, entry, pkg),
    integrity: str(own(entry, 'integrity')),
    dependencies: dependencyNames(entry, edges),
  };
  return slot === null ? raw : inSlot(raw, slot);
}

/** v2 and v3 `packages`: the slot is the name after the last `node_modules/`. */
function readNpmPackages(packages: JsonObject, entries: RawEntry[]): void {
  for (const [key, value] of Object.entries(packages)) {
    if (key === '') continue;
    const cut = key.lastIndexOf(NODE_MODULES);
    const slot = cut < 0 ? null : key.slice(cut + NODE_MODULES.length);
    entries.push(npmEntry(key, slot, objectAt(value, key), PACKAGE_EDGES));
  }
}

/** v1 (and v2) nested `dependencies`, walked with a stack; dependencies from `requires`. */
function readNpmDependencies(dependencies: JsonObject, entries: RawEntry[]): void {
  const pending = [dependencies];
  for (let level = pending.pop(); level !== undefined; level = pending.pop()) {
    for (const [slot, value] of Object.entries(level)) {
      const object = objectAt(value, slot);
      entries.push(npmEntry(NODE_MODULES + slot, slot, object, V1_EDGES));
      const nested = own(object, 'dependencies');
      if (isObject(nested)) pending.push(nested);
    }
  }
}

/** The format: `npm-<lockfileVersion>`. */
function npmFormat(lock: JsonObject): string {
  const version = own(lock, 'lockfileVersion');
  return `npm-${typeof version === 'number' ? version : 'none'}`;
}

/**
 * `package-lock.json` and `npm-shrinkwrap.json`: the v2/v3 `packages` and the v1 `dependencies`.
 * A v2 lockfile has both, and npm 6 installs from `dependencies`, so both are read.
 */
export function parseNpmLock(text: string): ReadLock {
  const lock = objectAt(JSON.parse(stripBom(text)), 'package-lock.json');
  const entries: RawEntry[] = [];
  readNpmPackages(sectionOf(lock, 'packages'), entries);
  readNpmDependencies(sectionOf(lock, 'dependencies'), entries);
  return { format: npmFormat(lock), entries: withDependents(entries) };
}

export function readNpmLock(text: string): LockEntry[] {
  return parseNpmLock(text).entries;
}
