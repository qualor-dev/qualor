/**
 * Yarn Berry lockfiles (`yarn.lock` with `__metadata`) as lock entries, read as YAML the way
 * Berry reads them (every scalar a string), each entry from its `resolution`.
 */
import {
  dependencyNames,
  inSlot,
  objectAt,
  resolvedKind,
  splitDescriptor,
  unreadable,
  withDependents,
  type RawEntry,
  type ReadLock,
} from './lock-read';
import type { LockEntryKind } from './types';
import { own, parseUrl, parseYaml, str, type JsonObject } from './values';

interface BerryLocator {
  kind: LockEntryKind;
  /** The archive URL of a registry package (null without one); the reference for the others. */
  source: string | null;
  /** The version a registry reference names; null for other protocols. */
  version: string | null;
}

/** Berry protocols other than `npm:`, `patch:`, git and http(s). */
const BERRY_KINDS: ReadonlyMap<string, LockEntryKind> = new Map([
  ['workspace:', 'path'],
  ['file:', 'file'],
  ['link:', 'link'],
  ['portal:', 'link'],
]);

/** A git repository behind an http(s) reference (`….git#commit=…`). */
const BERRY_GIT_URL = /\.git(?:#|$)|#commit=/;

/** A builtin compat patch Yarn applies to a registry package. */
const BUILTIN_PATCH = /^(?:optional!)?builtin<compat\/[\w.-]+>$/;

/** A reference and its binding parameters (`…::a=1&b=2`). */
function splitParams(reference: string): [string, string] {
  const cut = reference.indexOf('::');
  return cut < 0 ? [reference, ''] : [reference.slice(0, cut), reference.slice(cut + 2)];
}

/**
 * `npm:<version>`: a registry package. Berry fetches it from `__archiveUrl` when that parameter is
 * set, so that URL is its source (null without one), and it must be the registry tarball of this
 * package and version (fix round 1, C2), else the entry is a `tarball`. Two such parameters, or one
 * that is not a URL, are refused (Berry refuses them too).
 */
function berryNpm(reference: string, name: string): BerryLocator {
  const [selector, params] = splitParams(reference.slice('npm:'.length));
  const archive = new URLSearchParams(params).getAll('__archiveUrl');
  const url = archive[0] ?? null;
  if (archive.length > 1 || (url !== null && parseUrl(url) === null)) unreadable(reference);
  const kind = url === null ? 'registry' : resolvedKind(url, name, selector);
  return { kind, source: url, version: selector };
}

function other(reference: string): BerryLocator {
  return { kind: 'other', source: reference, version: null };
}

function decoded(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return '';
  }
}

/**
 * `patch:<descriptor>#<patch>`: a builtin compat patch of an `npm:` package counts as that registry
 * package (with its archive URL, if any) when it patches this very package at this entry's
 * version (fix round 1, C2: PatchFetcher fetches the inner package, and skips an optional patch
 * that fails); anything else is `other`. A patch file of the repository is `file`. The patched
 * package's checksum differs from the original's, so a new patch entry is checked as new.
 */
function berryPatch(reference: string, name: string, version: string | null): BerryLocator {
  const [body] = splitParams(reference.slice('patch:'.length));
  const hash = body.indexOf('#');
  if (hash < 0) return other(reference);
  if (!BUILTIN_PATCH.test(body.slice(hash + 1))) {
    return { kind: 'file', source: reference, version: null };
  }
  const original = splitDescriptor(decoded(body.slice(0, hash)));
  if (original?.name !== name || !original.range.startsWith('npm:')) return other(reference);
  const npm = berryNpm(original.range, name);
  return npm.version === version ? npm : other(reference);
}

function berryKind(protocol: string, reference: string): LockEntryKind {
  if (protocol.startsWith('git')) return 'git';
  if (protocol === 'http:' || protocol === 'https:') {
    return BERRY_GIT_URL.test(reference) ? 'git' : 'tarball';
  }
  return BERRY_KINDS.get(protocol) ?? 'other';
}

/**
 * The kind, source and registry version of a resolution's reference (after `name@`), for the
 * package `name` whose entry gives `version`.
 */
function berryReference(reference: string, name: string, version: string | null): BerryLocator {
  const protocol = reference.slice(0, reference.indexOf(':') + 1);
  if (protocol === 'npm:') return berryNpm(reference, name);
  if (protocol === 'patch:') return berryPatch(reference, name, version);
  return { kind: berryKind(protocol, reference), source: reference, version: null };
}

/** The names a key's descriptors (`a@npm:^1, b@npm:^2`) declare: the entry's slots. */
function descriptorSlots(key: string): string[] {
  const slots = key.split(',').map((d) => (splitDescriptor(d.trim()) ?? unreadable(key)).name);
  return [...new Set(slots)];
}

/** The dependency maps of an entry (Rulings T3e and T3j follow them all). */
const ENTRY_EDGES = ['dependencies', 'peerDependencies'];

/** Fix round 1, C4: Yarn 1 fields in a Berry entry would be read by Yarn 1 alone. */
const CLASSIC_FIELDS = ['resolved', 'integrity'];

/**
 * One entry per slot its key declares: the package from its `resolution` (an alias where a
 * descriptor names another package, fix round 1 C1), its `checksum` as integrity.
 */
function berryEntries(key: string, entry: JsonObject): RawEntry[] {
  if (CLASSIC_FIELDS.some((field) => own(entry, field) !== undefined)) unreadable(key);
  const resolution = str(own(entry, 'resolution')) ?? unreadable(key);
  const { name, range } = splitDescriptor(resolution) ?? unreadable(resolution);
  const version = str(own(entry, 'version'));
  const locator = berryReference(range, name, version);
  const raw: RawEntry = {
    name,
    version: locator.version ?? version ?? unreadable(key),
    kind: locator.kind,
    source: locator.source,
    integrity: str(own(entry, 'checksum')),
    dependencies: dependencyNames(entry, ENTRY_EDGES),
  };
  return descriptorSlots(key).map((slot) => inSlot(raw, slot));
}

/**
 * Yarn Berry: YAML with every scalar a string, as Berry reads it; dependents from `dependencies`
 * and `peerDependencies`. The format is `yarn-berry-<__metadata.version>`.
 */
export function parseYarnBerry(source: string): ReadLock {
  const lock = objectAt(parseYaml(source, { schema: 'failsafe' }), 'yarn.lock');
  const metadata = objectAt(own(lock, '__metadata'), '__metadata');
  const entries: RawEntry[] = [];
  for (const [key, value] of Object.entries(lock)) {
    if (key !== '__metadata') entries.push(...berryEntries(key, objectAt(value, key)));
  }
  const format = `yarn-berry-${str(own(metadata, 'version')) ?? 'none'}`;
  return { format, entries: withDependents(entries) };
}
