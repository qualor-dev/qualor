/**
 * pnpm lockfiles (`pnpm-lock.yaml`, v5 to v9) as {@link LockEntry} lists: the `packages` entries,
 * the importers' links, and every reference that puts another package in a slot
 * (`qf-a: evil@1.2.6`, fix round 1 C1).
 */
import {
  PACKAGE_NAME,
  dependencyNames,
  objectAt,
  sectionOf,
  splitDescriptor,
  unreadable,
  withDependents,
  type Edge,
  type RawEntry,
  type ReadLock,
} from './lock-read';
import type { LockEntry } from './types';
import { isObject, own, parseYaml, str, type JsonObject } from './values';

interface PackageId {
  name: string;
  version: string;
}

/** The sections whose names are a package's dependencies (Ruling T3e follows them). */
const DEPENDENCY_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'];
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
): RawEntry {
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

function pnpmEntry(key: string, value: unknown, major: number): RawEntry {
  const entry = objectAt(value, key);
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

/** v9 `snapshots`: the dependencies of each package instance. */
function pnpmSnapshotEdges(snapshots: JsonObject): Edge[] {
  return Object.entries(snapshots).map(([key, value]) => ({
    from: (splitAtVersion(key) ?? unreadable(key)).name,
    to: dependencyNames(value, INSTANCE_EDGES),
  }));
}

/** A dependency's reference: a plain string, or the `version` of a `{ specifier, version }`. */
function referenceOf(value: unknown): string | null {
  return isObject(value) ? str(own(value, 'version')) : str(value);
}

/**
 * The package a reference names when it is more than a version: `evil@1.2.6` (v9),
 * `/evil@1.2.6` (v6) or `/evil/1.2.6` (v5), a peer suffix cut off.
 */
function referencedPackage(reference: string, major: number): PackageId | null {
  const bare = reference.split('(', 1)[0] ?? '';
  const parts = bare.startsWith('/') ? pnpmKeyParts(bare, major) : splitAtVersion(bare);
  return parts !== null && PACKAGE_NAME.test(parts.name) ? parts : null;
}

interface References {
  major: number;
  /** The `packages` entries by `name@version`. */
  packages: ReadonlyMap<string, RawEntry>;
}

/**
 * One dependency as an entry of its own when it is a link (`link:…`, no `packages` entry) or puts
 * another package in its slot (an alias: the referenced entry, in that slot).
 */
function referenceEntry(slot: string, value: unknown, refs: References): RawEntry | null {
  const reference = referenceOf(value);
  if (reference === null) return null;
  if (reference.startsWith('link:')) {
    return { name: slot, version: '', source: reference, kind: 'link', integrity: null };
  }
  const target = referencedPackage(reference, refs.major);
  if (target === null || target.name === slot) return null;
  const found = refs.packages.get(`${target.name}@${target.version}`);
  return { ...(found ?? { ...target, kind: 'other', source: null, integrity: null }), slot };
}

function holderReferences(holder: unknown, refs: References): RawEntry[] {
  const entries: RawEntry[] = [];
  for (const section of DEPENDENCY_SECTIONS) {
    const deps = isObject(holder) ? own(holder, section) : undefined;
    if (!isObject(deps)) continue;
    for (const [slot, value] of Object.entries(deps)) {
      const entry = referenceEntry(slot, value, refs);
      if (entry !== null) entries.push(entry);
    }
  }
  return entries;
}

/**
 * The links and aliases among the dependencies of the importers (and of a single-project v5 or
 * v6 lockfile's top level) and of every package instance (v9 `snapshots`, v5/v6 `packages`).
 */
function pnpmReferences(lock: JsonObject, major: number, entries: readonly RawEntry[]): RawEntry[] {
  const packages = new Map(entries.map((entry) => [`${entry.name}@${entry.version}`, entry]));
  const instances = sectionOf(lock, major >= 9 ? 'snapshots' : 'packages');
  const holders = [
    ...Object.values(sectionOf(lock, 'importers')),
    lock,
    ...Object.values(instances),
  ];
  return holders.flatMap((holder) => holderReferences(holder, { major, packages }));
}

/**
 * `pnpm-lock.yaml`: v5 `/a/1.0.0`, v6 `/a@1.0.0` and v9 `a@1.0.0` package keys, the links and
 * aliases of the references; dependents from v9 `snapshots` or the v5/v6 packages' dependencies.
 * The format is `pnpm-<major>`.
 */
export function parsePnpmLock(text: string): ReadLock {
  const lock = objectAt(parseYaml(text, { merge: true }), 'pnpm-lock.yaml');
  const major = pnpmMajor(lock);
  const packages = Object.entries(sectionOf(lock, 'packages'));
  const entries = packages.map(([key, value]) => pnpmEntry(key, value, major));
  const edges =
    major >= 9
      ? pnpmSnapshotEdges(sectionOf(lock, 'snapshots'))
      : packages.map(([, value], i) => ({
          from: entries[i]?.name ?? '',
          to: dependencyNames(value, INSTANCE_EDGES),
        }));
  const all = [...entries, ...pnpmReferences(lock, major, entries)];
  return { format: `pnpm-${major}`, entries: withDependents(all, edges) };
}

export function readPnpmLock(text: string): LockEntry[] {
  return parsePnpmLock(text).entries;
}
