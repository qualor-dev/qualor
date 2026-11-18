/**
 * pnpm lockfiles (`pnpm-lock.yaml`, v5 to v9) as {@link LockEntry} lists: the `packages` entries,
 * the importers' links, and every reference that puts another package in a slot
 * (`qf-a: evil@1.2.6`, fix round 1 C1).
 */
import { versionParses } from '../versions';
import {
  dependencyNames,
  entryCounter,
  objectAt,
  sectionOf,
  splitDescriptor,
  unreadable,
  withDependents,
  type RawEntry,
  type ReadLock,
} from './lock-read';
import type { LockEntry } from './types';
import { isObject, own, parseYamlDocuments, str, type JsonObject } from './values';

interface PackageId {
  name: string;
  version: string;
}

/** The dependency maps of an importer or a package instance (references are read from all). */
const DEPENDENCY_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'];

/** The dependency maps of a package (Rulings T3e and T3l follow them all). */
const INSTANCE_EDGES = ['dependencies', 'optionalDependencies'];

function pnpmMajor(lock: JsonObject): number {
  const version = own(lock, 'lockfileVersion');
  const text = typeof version === 'number' || typeof version === 'string' ? String(version) : '';
  const major = Number.parseInt(text, 10);
  if (Number.isNaN(major) || major < 5) unreadable('lockfileVersion');
  return major;
}

/** `name@version`, a peer suffix `(…)` cut off (v6, v9). */
function splitAtVersion(text: string): PackageId | null {
  const parts = splitDescriptor(text);
  const version = parts?.range.split('(', 1)[0] ?? '';
  return parts === null || version === '' ? null : { name: parts.name, version };
}

/** v5 `/name/version`, a peer suffix `_…` cut off (peer scopes are written with `+`). */
function splitV5(key: string): PackageId | null {
  const slash = key.lastIndexOf('/');
  const name = key.slice(1, slash);
  const version = key.slice(slash + 1).split('_', 1)[0] ?? '';
  return !key.startsWith('/') || name === '' || version === '' ? null : { name, version };
}

function pnpmKeyParts(key: string, major: number): PackageId | null {
  if (major < 6) return splitV5(key);
  return splitAtVersion(major < 9 && key.startsWith('/') ? key.slice(1) : key);
}

type Resolution = Pick<RawEntry, 'kind' | 'source' | 'integrity'>;

function typedResolution(resolution: JsonObject, type: string): Pick<RawEntry, 'kind' | 'source'> {
  if (type === 'git') return { kind: 'git', source: str(own(resolution, 'repo')) };
  if (type === 'directory') return { kind: 'path', source: str(own(resolution, 'directory')) };
  return { kind: 'other', source: null };
}

/** `{integrity}` is a registry package; `tarball`, `type: git` and `type: directory` are not. */
function pnpmResolution(value: unknown): Resolution {
  if (!isObject(value)) return { kind: 'other', source: null, integrity: null };
  const integrity = str(own(value, 'integrity'));
  const type = str(own(value, 'type'));
  if (type !== null) return { ...typedResolution(value, type), integrity };
  const tarball = str(own(value, 'tarball'));
  if (tarball !== null) {
    return { kind: /^file:/i.test(tarball) ? 'file' : 'tarball', source: tarball, integrity };
  }
  return { kind: integrity === null ? 'other' : 'registry', source: null, integrity };
}

interface PnpmFields {
  name: string | null;
  version: string | null;
}

/** An entry before its dependencies are known. */
type Located = Omit<RawEntry, 'dependencies'>;

/**
 * Ruling T3b: pnpm fetches a registry package (integrity only) by its key, so the key names it.
 * `name` or `version` fields that disagree with the key, or a key without a version, make the
 * entry `other`, so a new one is refused.
 */
function pnpmRegistryEntry(
  key: string,
  parts: PackageId | null,
  fields: PnpmFields,
  resolution: Resolution,
): Located {
  const agrees =
    parts !== null &&
    (fields.name ?? parts.name) === parts.name &&
    (fields.version ?? parts.version) === parts.version;
  return {
    name: parts?.name ?? fields.name ?? unreadable(key),
    version: parts?.version ?? fields.version ?? unreadable(key),
    ...resolution,
    kind: agrees ? 'registry' : 'other',
  };
}

function pnpmLocated(key: string, entry: JsonObject, major: number): Located {
  const parts = pnpmKeyParts(key, major);
  const fields = { name: str(own(entry, 'name')), version: str(own(entry, 'version')) };
  const resolution = pnpmResolution(own(entry, 'resolution'));
  if (resolution.kind === 'registry') return pnpmRegistryEntry(key, parts, fields, resolution);
  return {
    name: fields.name ?? parts?.name ?? unreadable(key),
    version: fields.version ?? parts?.version ?? unreadable(key),
    ...resolution,
  };
}

/** v9 `snapshots`: the dependencies of every instance of a package, by its `packages` key. */
function snapshotDependencies(snapshots: JsonObject): Map<string, string[]> {
  const byPackage = new Map<string, string[]>();
  for (const [key, value] of Object.entries(snapshots)) {
    const packageKey = key.split('(', 1)[0] ?? key;
    const names = byPackage.get(packageKey) ?? [];
    names.push(...dependencyNames(value, INSTANCE_EDGES));
    byPackage.set(packageKey, names);
  }
  return byPackage;
}

/** A `packages` entry, depending on its v5/v6 dependency maps or on its v9 snapshots'. */
function pnpmEntry(
  key: string,
  value: unknown,
  major: number,
  snapshots: ReadonlyMap<string, string[]> | null,
): RawEntry {
  const entry = objectAt(value, key);
  const dependencies =
    snapshots === null ? dependencyNames(entry, INSTANCE_EDGES) : (snapshots.get(key) ?? []);
  return { ...pnpmLocated(key, entry, major), dependencies };
}

/** A dependency's reference: a plain string, or the `version` of a `{ specifier, version }`. */
function referenceOf(value: unknown): string | null {
  return isObject(value) ? str(own(value, 'version')) : str(value);
}

/**
 * A reference without its v5 peers. Fix round 2, N2: a v5 reference carries them after the first
 * `_` (`1.0.0_react@18.2.0`), as v5 keys do; v6 and v9 put them in `(…)`, cut off before.
 */
function withoutV5Peers(bare: string, major: number): string {
  return major < 6 ? (bare.split('_', 1)[0] ?? '') : bare;
}

/**
 * The package a reference names when it is more than a version: `evil@1.2.6` (v9),
 * `/evil@1.2.6` (v6) or `/evil/1.2.6` (v5), a peer suffix cut off. A reference with an `@` that
 * names no package (a git URL, say) is read the same way, so it fails closed: an alias, refused
 * unless the base has it (fix round 1).
 */
function referencedPackage(reference: string, major: number): PackageId | null {
  const bare = reference.split('(', 1)[0] ?? '';
  if (bare.startsWith('/')) return pnpmKeyParts(bare, major);
  return splitAtVersion(withoutV5Peers(bare, major));
}

/**
 * Whether pnpm takes a reference as the depPath itself, whatever the slot: in v5 and v6, one
 * with a path (fix round 3, NB3) or a `file:` one (fix round 4, R4-2), as pnpm's `refToRelative`
 * does. v9 puts the slot's name in front of both.
 */
function isDepPath(bare: string, major: number): boolean {
  return major < 9 && !bare.startsWith('/') && (bare.includes('/') || bare.startsWith('file:'));
}

/** A reference that stands for no `packages` entry: an alias of kind `other` (fail closed). */
function unknownReference(slot: string, reference: string): RawEntry {
  const unknown = { name: reference, version: '', source: null, integrity: null };
  return { ...unknown, kind: 'other', dependencies: [], slot };
}

interface References {
  major: number;
  /** The `packages` entries by `name@version`. */
  packages: ReadonlyMap<string, RawEntry>;
  /** The `packages` entries by their key (depPath). */
  byKey: ReadonlyMap<string, RawEntry>;
  /** Counts each entry made against the budget, and stops the read over it (fix round 5). */
  count: (entry: RawEntry) => RawEntry;
}

/**
 * Fix round 3 NB3, fix round 4 R4-2: a v5 or v6 depPath reference
 * (`registry.example.com/foo/1.0.0_react@…`, `github.com/x/foo/<sha>`, `file:foo-1.0.0.tgz`) is
 * the key of a `packages` entry, whatever the slot; an alias when that entry is another package,
 * an unknown alias (fail closed) when there is none. v9 keys hold the slot's name, so a v9
 * reference cannot point a slot elsewhere this way.
 */
function depPathEntry(slot: string, depPath: string, refs: References): RawEntry | null {
  const found = refs.byKey.get(depPath);
  if (found === undefined) return unknownReference(slot, depPath);
  return found.name === slot ? null : { ...found, slot };
}

/**
 * One dependency as an entry of its own when it is a link (`link:…`, no `packages` entry) or puts
 * another package in its slot (an alias: the referenced entry, in that slot). A reference that
 * names no package must be a plain version; anything else is an unknown alias (fix round 4, R4-2:
 * fail closed).
 */
function referenceEntry(slot: string, value: unknown, refs: References): RawEntry | null {
  const reference = referenceOf(value);
  if (reference === null) return null;
  if (reference.startsWith('link:')) {
    const link = { name: slot, version: '', source: reference, integrity: null };
    return { ...link, kind: 'link', dependencies: [] };
  }
  const bare = reference.split('(', 1)[0] ?? '';
  if (isDepPath(bare, refs.major)) {
    return depPathEntry(slot, refs.byKey.has(reference) ? reference : bare, refs);
  }
  const target = referencedPackage(reference, refs.major);
  if (target === null) {
    const plain = versionParses('semver', withoutV5Peers(bare, refs.major));
    return plain ? null : unknownReference(slot, bare);
  }
  if (target.name === slot) return null;
  const found = refs.packages.get(`${target.name}@${target.version}`);
  const missing = { ...target, kind: 'other' as const, source: null, integrity: null };
  return { ...(found ?? { ...missing, dependencies: [] }), slot };
}

function holderReferences(holder: unknown, refs: References): RawEntry[] {
  const entries: RawEntry[] = [];
  for (const section of DEPENDENCY_SECTIONS) {
    const deps = isObject(holder) ? own(holder, section) : undefined;
    if (!isObject(deps)) continue;
    for (const [slot, value] of Object.entries(deps)) {
      const entry = referenceEntry(slot, value, refs);
      if (entry !== null) entries.push(refs.count(entry));
    }
  }
  return entries;
}

/**
 * The links and aliases among the dependencies of the importers (and of a single-project v5 or
 * v6 lockfile's top level) and of every package instance (v9 `snapshots`, v5/v6 `packages`).
 * Each entry is counted as it is made, so the walk stops as soon as the budget is spent (fix
 * round 5, R5-2).
 */
function pnpmReferences(
  lock: JsonObject,
  major: number,
  byKey: ReadonlyMap<string, RawEntry>,
  count: (entry: RawEntry) => RawEntry,
): RawEntry[] {
  const entries = [...byKey.values()];
  const packages = new Map(entries.map((entry) => [`${entry.name}@${entry.version}`, entry]));
  const instances = sectionOf(lock, major >= 9 ? 'snapshots' : 'packages');
  const holders = [
    ...Object.values(sectionOf(lock, 'importers')),
    lock,
    ...Object.values(instances),
  ];
  const refs = { major, packages, byKey, count };
  return holders.flatMap((holder) => holderReferences(holder, refs));
}

/** What pnpm 11's boot document holds: the root importer's two kinds of boot dependencies. */
const BOOT_KEYS = new Set(['lockfileVersion', 'settings', 'importers', 'packages', 'snapshots']);
const BOOT_DEPENDENCIES = ['configDependencies', 'packageManagerDependencies'];

/**
 * Ruling T4b: the first of two documents must be pnpm 11's boot document: an importer `.` with
 * `configDependencies` and/or `packageManagerDependencies` and nothing else, besides
 * `lockfileVersion`, `settings`, `packages` and `snapshots`.
 */
function bootDocument(value: unknown): JsonObject {
  const boot = objectAt(value, 'the boot document');
  const importers = sectionOf(boot, 'importers');
  const root = objectAt(own(importers, '.'), 'the boot document importer');
  const rootKeys = Object.keys(root);
  const shaped =
    Object.keys(boot).every((key) => BOOT_KEYS.has(key)) &&
    Object.keys(importers).length === 1 &&
    rootKeys.length > 0 &&
    rootKeys.every((key) => BOOT_DEPENDENCIES.includes(key));
  return shaped ? boot : unreadable('a first document that is no pnpm boot document');
}

/**
 * Ruling T4b: the lockfile document holds no boot dependencies, wherever pnpm might read them
 * from (an importer, or a v5/v6 single-project lockfile's top level).
 */
function assertNoBootDependencies(lock: JsonObject): void {
  const holders = [lock, ...Object.values(sectionOf(lock, 'importers'))];
  const found = holders.some(
    (holder) => isObject(holder) && BOOT_DEPENDENCIES.some((key) => Object.hasOwn(holder, key)),
  );
  if (found) unreadable('boot dependencies in the lockfile document');
}

/**
 * Ruling T4b: the lockfile document and, when the file has two documents, the boot document
 * before it. Three or more documents throw.
 */
function pnpmDocuments(text: string): { lock: JsonObject; boot?: JsonObject } {
  const docs = parseYamlDocuments(text, {}, 2);
  const [first, second] = docs;
  const lock = objectAt(second ?? first, 'pnpm-lock.yaml');
  assertNoBootDependencies(lock);
  return second === undefined ? { lock } : { lock, boot: bootDocument(first) };
}

/**
 * `pnpm-lock.yaml`: v5 `/a/1.0.0`, v6 `/a@1.0.0` and v9 `a@1.0.0` package keys with their
 * dependencies (v9 `snapshots`, or the v5/v6 packages' own), and the links and aliases of the
 * references. The format is `pnpm-<major>`. Rulings T3o and T3p: no YAML anchors, aliases, merge
 * keys, tags, directives or keys that are not strings (pnpm writes none). Ruling T4b: pnpm 11
 * writes its boot document (config and package-manager dependencies) first, as a document of its
 * own; it is returned as `boot` and not read for entries. Fix round 5 (R5-2): the dependency
 * names of the entries are counted while they are made, and the read stops as soon as the count
 * is over the budget.
 */
export function parsePnpmLock(text: string): ReadLock {
  const { lock, boot } = pnpmDocuments(text);
  const major = pnpmMajor(lock);
  const count = entryCounter('pnpm packages and references');
  const snapshots = major >= 9 ? snapshotDependencies(sectionOf(lock, 'snapshots')) : null;
  const byKey = new Map<string, RawEntry>();
  for (const [key, value] of Object.entries(sectionOf(lock, 'packages'))) {
    byKey.set(key, count(pnpmEntry(key, value, major, snapshots)));
  }
  const all = [...byKey.values(), ...pnpmReferences(lock, major, byKey, count)];
  const read: ReadLock = { format: `pnpm-${major}`, entries: withDependents(all) };
  return boot === undefined ? read : { ...read, boot };
}

export function readPnpmLock(text: string): LockEntry[] {
  return parsePnpmLock(text).entries;
}
