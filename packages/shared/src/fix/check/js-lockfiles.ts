/**
 * B1 for JS lockfiles (spec §12): npm (`package-lock.json`, `npm-shrinkwrap.json`, v1 to v3), pnpm
 * (`pnpm-lock.yaml`, v5 to v9) and Yarn (`yarn.lock`, classic and Berry) are read into
 * {@link LockEntry} lists, then checked by {@link checkLockEntries} and {@link lockfileBelowTarget}.
 * The readers throw on a file they cannot read; {@link checkJsLockfile} answers `unparsable`.
 */
import { checkLockEntries, lockfileBelowTarget } from './lock-entries';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
  type LockEntry,
  type LockEntryKind,
} from './types';
import { isObject, own, parseYaml, str, stripBom, type JsonObject } from './values';

/** An entry before its dependents are known. */
type RawEntry = Omit<LockEntry, 'dependents'>;

/** `from` depends on each package named in `to`. */
interface Edge {
  from: string;
  to: readonly string[];
}

function unreadable(what: string): never {
  throw new Error(`unreadable lockfile at ${what.slice(0, 200)}`);
}

function objectAt(value: unknown, what: string): JsonObject {
  if (!isObject(value)) unreadable(what);
  return value;
}

/** An object-valued section; an empty object when it is absent or null. */
function sectionOf(object: JsonObject, key: string): JsonObject {
  const value = own(object, key);
  return value === undefined || value === null ? {} : objectAt(value, key);
}

/** The package names of an entry's dependency map. */
function dependencyNames(entry: unknown, key: string): string[] {
  const deps = isObject(entry) ? own(entry, key) : undefined;
  return isObject(deps) ? Object.keys(deps) : [];
}

/** Each entry gets the sorted names of the packages that depend on its name; duplicates go. */
function withDependents(raw: readonly RawEntry[], edges: readonly Edge[]): LockEntry[] {
  const dependents = new Map<string, Set<string>>();
  for (const { from, to } of edges) {
    for (const name of to) {
      const names = dependents.get(name) ?? new Set<string>();
      names.add(from);
      dependents.set(name, names);
    }
  }
  const seen = new Set<string>();
  const entries: LockEntry[] = [];
  for (const entry of raw) {
    const key = JSON.stringify([
      entry.name,
      entry.version,
      entry.source,
      entry.kind,
      entry.integrity,
    ]);
    if (seen.has(key)) continue;
    seen.add(key);
    const names = [...(dependents.get(entry.name) ?? [])].sort((a, b) => a.localeCompare(b));
    entries.push({ ...entry, dependents: names });
  }
  return entries;
}

/** `name@range`, the name possibly scoped; null without an `@` after the first character. */
function splitDescriptor(text: string): { name: string; range: string } | null {
  const atSign = text.indexOf('@', 1);
  return atSign < 1 ? null : { name: text.slice(0, atSign), range: text.slice(atSign + 1) };
}

// ---------------------------------------------------------------------------------------------
// Source kinds

/** Spec and version prefixes that name a source other than a registry. */
const SPEC_KINDS: readonly (readonly [RegExp, LockEntryKind])[] = [
  [/^(?:git\+|git:|git@|ssh:|github:|gitlab:|bitbucket:|gist:)/i, 'git'],
  [/^file:/i, 'file'],
  [/^link:/i, 'link'],
  [/^https?:\/\//i, 'tarball'],
];

/** The kind a dependency spec or a version names; null for a registry spec (version, range, tag). */
function specKind(spec: string): LockEntryKind | null {
  return SPEC_KINDS.find(([pattern]) => pattern.test(spec))?.[1] ?? null;
}

const HTTP_AUTHORITY = /^https?:\/\/[^/?#\\]*/i;

/**
 * The kind of a `resolved` URL (npm, Yarn classic). An http(s) URL whose path has a `/-/` segment
 * is a registry tarball, as npm registries name them (`<registry>/<name>/-/<name>-<v>.tgz`); any
 * other http(s) URL is a tarball dependency.
 */
function resolvedKind(resolved: string): LockEntryKind {
  const authority = HTTP_AUTHORITY.exec(resolved);
  if (authority === null) return specKind(resolved) ?? 'other';
  const path = resolved.slice(authority[0].length).split(/[?#]/, 1)[0] ?? '';
  return path.includes('/-/') ? 'registry' : 'tarball';
}

// ---------------------------------------------------------------------------------------------
// npm

const NODE_MODULES = 'node_modules/';

/** The kind and source of an npm entry: `link`, a URL or `file:` version, or its `resolved`. */
function npmSource(key: string, entry: JsonObject): Pick<RawEntry, 'kind' | 'source'> {
  const resolved = str(own(entry, 'resolved'));
  if (own(entry, 'link') === true) return { kind: 'link', source: resolved };
  const version = str(own(entry, 'version'));
  const versionKind = version === null ? null : specKind(version);
  if (versionKind !== null) return { kind: versionKind, source: resolved ?? version };
  if (resolved !== null) return { kind: resolvedKind(resolved), source: resolved };
  return { kind: key.includes(NODE_MODULES) ? 'registry' : 'path', source: null };
}

function npmEntry(key: string, name: string, entry: JsonObject): RawEntry {
  return {
    name: str(own(entry, 'name')) ?? name,
    version: str(own(entry, 'version')) ?? '',
    ...npmSource(key, entry),
    integrity: str(own(entry, 'integrity')),
  };
}

/** v2 and v3 `packages`: the name after the last `node_modules/` (or the entry's `name`). */
function readNpmPackages(packages: JsonObject, entries: RawEntry[], edges: Edge[]): void {
  for (const [key, value] of Object.entries(packages)) {
    if (key === '') continue;
    const cut = key.lastIndexOf(NODE_MODULES);
    const name = cut < 0 ? key : key.slice(cut + NODE_MODULES.length);
    const entry = npmEntry(key, name, objectAt(value, key));
    entries.push(entry);
    edges.push({ from: entry.name, to: dependencyNames(value, 'dependencies') });
  }
}

/** v1 (and v2) nested `dependencies`, walked with a stack; dependents from `requires`. */
function readNpmDependencies(dependencies: JsonObject, entries: RawEntry[], edges: Edge[]): void {
  const pending = [dependencies];
  for (let level = pending.pop(); level !== undefined; level = pending.pop()) {
    for (const [name, value] of Object.entries(level)) {
      const object = objectAt(value, name);
      const entry = npmEntry(NODE_MODULES + name, name, object);
      entries.push(entry);
      edges.push({ from: entry.name, to: dependencyNames(object, 'requires') });
      const nested = own(object, 'dependencies');
      if (isObject(nested)) pending.push(nested);
    }
  }
}

/**
 * `package-lock.json` and `npm-shrinkwrap.json`: the v2/v3 `packages` and the v1 `dependencies`.
 * A v2 lockfile has both, and npm 6 installs from `dependencies`, so both are read.
 */
export function readNpmLock(text: string): LockEntry[] {
  const lock = objectAt(JSON.parse(stripBom(text)), 'package-lock.json');
  const entries: RawEntry[] = [];
  const edges: Edge[] = [];
  readNpmPackages(sectionOf(lock, 'packages'), entries, edges);
  readNpmDependencies(sectionOf(lock, 'dependencies'), entries, edges);
  return withDependents(entries, edges);
}

// ---------------------------------------------------------------------------------------------
// pnpm

function pnpmMajor(lock: JsonObject): number {
  const version = own(lock, 'lockfileVersion');
  const text = typeof version === 'number' || typeof version === 'string' ? String(version) : '';
  const major = Number.parseInt(text, 10);
  if (Number.isNaN(major) || major < 5) unreadable('lockfileVersion');
  return major;
}

/** `name@version`, a peer suffix `(…)` cut off (v6, v9). */
function splitAtVersion(text: string): { name: string; version: string } | null {
  const parts = splitDescriptor(text);
  const version = parts?.range.split('(', 1)[0] ?? '';
  return parts === null || version === '' ? null : { name: parts.name, version };
}

/** v5 `/name/version`, a peer suffix `_…` cut off (peer scopes are written with `+`). */
function splitV5(key: string): { name: string; version: string } | null {
  const slash = key.lastIndexOf('/');
  const name = key.slice(1, slash);
  const version = key.slice(slash + 1).split('_', 1)[0] ?? '';
  return !key.startsWith('/') || name === '' || version === '' ? null : { name, version };
}

function pnpmKeyParts(key: string, major: number): { name: string; version: string } | null {
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

function pnpmEntry(key: string, value: unknown, major: number): RawEntry {
  const entry = objectAt(value, key);
  const parts = pnpmKeyParts(key, major);
  return {
    name: str(own(entry, 'name')) ?? parts?.name ?? unreadable(key),
    version: str(own(entry, 'version')) ?? parts?.version ?? unreadable(key),
    ...pnpmResolution(own(entry, 'resolution')),
  };
}

/** v9 `snapshots`: the dependencies of each package instance. */
function pnpmSnapshotEdges(snapshots: JsonObject): Edge[] {
  return Object.entries(snapshots).map(([key, value]) => ({
    from: (splitAtVersion(key) ?? unreadable(key)).name,
    to: dependencyNames(value, 'dependencies'),
  }));
}

const IMPORTER_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'];

/** A direct dependency whose version is `link:…` (v5: the version itself; v6, v9: `{ version }`). */
function linkEntry(name: string, value: unknown): RawEntry[] {
  const version = isObject(value) ? str(own(value, 'version')) : str(value);
  if (version?.startsWith('link:') !== true) return [];
  return [{ name, version: '', source: version, kind: 'link', integrity: null }];
}

function importerLinks(importer: unknown): RawEntry[] {
  return IMPORTER_SECTIONS.flatMap((section) => {
    const deps = isObject(importer) ? own(importer, section) : undefined;
    return isObject(deps) ? Object.entries(deps).flatMap(([name, v]) => linkEntry(name, v)) : [];
  });
}

/**
 * pnpm links a direct dependency (`version: link:…`) without a `packages` entry, so such links are
 * read from each importer, and from the top level of a single-project v5 or v6 lockfile.
 */
function pnpmLinks(lock: JsonObject): RawEntry[] {
  return [...Object.values(sectionOf(lock, 'importers')), lock].flatMap(importerLinks);
}

/**
 * `pnpm-lock.yaml`: v5 `/a/1.0.0`, v6 `/a@1.0.0` and v9 `a@1.0.0` package keys (an entry's own
 * `name` and `version` win), and the importers' links; dependents from v9 `snapshots` or the v5/v6
 * packages' `dependencies`.
 */
export function readPnpmLock(text: string): LockEntry[] {
  const lock = objectAt(parseYaml(text, { merge: true }), 'pnpm-lock.yaml');
  const major = pnpmMajor(lock);
  const packages = Object.entries(sectionOf(lock, 'packages'));
  const entries = packages.map(([key, value]) => pnpmEntry(key, value, major));
  const edges =
    major >= 9
      ? pnpmSnapshotEdges(sectionOf(lock, 'snapshots'))
      : packages.map(([, value], i) => ({
          from: entries[i]?.name ?? '',
          to: dependencyNames(value, 'dependencies'),
        }));
  return withDependents([...entries, ...pnpmLinks(lock)], edges);
}

// ---------------------------------------------------------------------------------------------
// Yarn classic

/** Yarn breaks lines at `\r\n`, `\r` and `\n`. */
const LINE_BREAK = /\r\n|\r|\n/;

/** A JSON string, as Yarn quotes, or a bare token without space, quote, comma or colon. */
const TOKEN = /^(?:"(?:[^"\\]|\\.)*"|[^\s",:]+)/;
const PATTERN_SEPARATOR = /^, */;
const SPACES = /^ +/;

function unquote(token: string): string {
  return token.startsWith('"') ? String(JSON.parse(token)) : token;
}

interface ClassicBlock {
  patterns: string[];
  fields: Map<string, string>;
  /** Nested maps (`dependencies:`), by key: the names they list. */
  maps: Map<string, string[]>;
  /** The nested map the next 4-space lines belong to. */
  open: string[] | null;
}

interface ClassicLine {
  indent: number;
  text: string;
}

/** A line's indent (spaces only: 0, 2 or 4) and text; null for a blank or comment line. */
function classicLine(raw: string): ClassicLine | null {
  const line = raw.trimEnd();
  const text = line.trimStart();
  if (text === '' || text.startsWith('#')) return null;
  const indent = line.length - text.length;
  if (!/^ *$/.test(line.slice(0, indent)) || indent % 2 !== 0 || indent > 4) unreadable(raw);
  return { indent, text };
}

/** A block header: comma-separated patterns, then `:`. */
function classicHeader(text: string): ClassicBlock {
  if (!text.endsWith(':')) unreadable(text);
  const header = text.slice(0, -1);
  const patterns: string[] = [];
  let rest = header;
  for (;;) {
    const token = TOKEN.exec(rest) ?? unreadable(header);
    patterns.push(unquote(token[0]));
    rest = rest.slice(token[0].length);
    if (rest === '') return { patterns, fields: new Map(), maps: new Map(), open: null };
    rest = rest.slice((PATTERN_SEPARATOR.exec(rest) ?? unreadable(header))[0].length);
  }
}

/** `key value`, or `key:` that opens a nested map (value null). */
function classicPair(text: string): { key: string; value: string | null } {
  const key = TOKEN.exec(text) ?? unreadable(text);
  const rest = text.slice(key[0].length);
  if (rest === ':') return { key: unquote(key[0]), value: null };
  const valueText = rest.slice((SPACES.exec(rest) ?? unreadable(text))[0].length);
  const value = TOKEN.exec(valueText);
  if (value?.[0] !== valueText) unreadable(text);
  return { key: unquote(key[0]), value: unquote(valueText) };
}

/** A 2-space field or nested-map line, or a 4-space line of the open nested map. */
function classicBody(block: ClassicBlock, line: ClassicLine): void {
  const { key, value } = classicPair(line.text);
  if (line.indent === 4) {
    if (block.open === null || value === null) unreadable(line.text);
    block.open.push(key);
    return;
  }
  // Yarn keeps the last of two equal keys; refusing them keeps both readings the same.
  if (block.fields.has(key) || block.maps.has(key)) unreadable(line.text);
  block.open = value === null ? [] : null;
  if (block.open !== null) block.maps.set(key, block.open);
  if (value !== null) block.fields.set(key, value);
}

function classicBlocks(source: string): ClassicBlock[] {
  const blocks: ClassicBlock[] = [];
  for (const raw of source.split(LINE_BREAK)) {
    const line = classicLine(raw);
    if (line === null) continue;
    if (line.indent === 0) blocks.push(classicHeader(line.text));
    else classicBody(blocks.at(-1) ?? unreadable(raw), line);
  }
  return blocks;
}

/** The package a pattern names: `name@range`, or the target of an `npm:` alias. */
function classicPattern(pattern: string): { name: string; range: string } {
  const parts = splitDescriptor(pattern) ?? unreadable(pattern);
  if (!parts.range.startsWith('npm:')) return parts;
  const target = parts.range.slice('npm:'.length);
  return splitDescriptor(target) ?? { name: target, range: '' };
}

/** A range's own kind; a GitHub shorthand (`user/repo`) is git. */
function classicRangeKind(range: string): LockEntryKind | null {
  return specKind(range) ?? (range.includes('/') ? 'git' : null);
}

function classicKind(ranges: readonly string[], resolved: string | null): LockEntryKind {
  for (const range of ranges) {
    const kind = classicRangeKind(range);
    if (kind !== null) return kind;
  }
  return resolved === null ? 'registry' : resolvedKind(resolved);
}

/** Yarn classic: one entry per package its block's patterns name. */
function readYarnClassic(source: string): LockEntry[] {
  const entries: RawEntry[] = [];
  const edges: Edge[] = [];
  for (const block of classicBlocks(source)) {
    const patterns = block.patterns.map(classicPattern);
    const resolved = block.fields.get('resolved') ?? null;
    const fields = {
      version: block.fields.get('version') ?? unreadable(block.patterns.join(', ')),
      source: resolved,
      kind: classicKind(
        patterns.map((p) => p.range),
        resolved,
      ),
      integrity: block.fields.get('integrity') ?? null,
    };
    const dependencies = block.maps.get('dependencies') ?? [];
    for (const name of new Set(patterns.map((p) => p.name))) {
      entries.push({ name, ...fields });
      edges.push({ from: name, to: dependencies });
    }
  }
  return withDependents(entries, edges);
}

// ---------------------------------------------------------------------------------------------
// Yarn Berry

interface BerryLocator {
  kind: LockEntryKind;
  source: string;
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
 * set, so that URL is its source; two of them are refused (Berry refuses them too).
 */
function berryNpm(reference: string): BerryLocator {
  const [selector, params] = splitParams(reference.slice('npm:'.length));
  const archive = new URLSearchParams(params).getAll('__archiveUrl');
  if (archive.length > 1) unreadable(reference);
  return { kind: 'registry', source: archive[0] ?? reference, version: selector };
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
 * package (its source is the patch, or the archive URL); a patch file of the repository is `file`.
 */
function berryPatch(reference: string): BerryLocator {
  const [body] = splitParams(reference.slice('patch:'.length));
  const hash = body.indexOf('#');
  if (hash < 0) return { kind: 'other', source: reference, version: null };
  if (!BUILTIN_PATCH.test(body.slice(hash + 1))) {
    return { kind: 'file', source: reference, version: null };
  }
  const original = splitDescriptor(decoded(body.slice(0, hash)));
  if (original?.range.startsWith('npm:') !== true) {
    return { kind: 'other', source: reference, version: null };
  }
  const npm = berryNpm(original.range);
  return { ...npm, source: npm.source === original.range ? reference : npm.source };
}

function berryKind(protocol: string, reference: string): LockEntryKind {
  if (protocol.startsWith('git')) return 'git';
  if (protocol === 'http:' || protocol === 'https:') {
    return BERRY_GIT_URL.test(reference) ? 'git' : 'tarball';
  }
  return BERRY_KINDS.get(protocol) ?? 'other';
}

/** The kind, source and registry version of a resolution's reference (after `name@`). */
function berryReference(reference: string): BerryLocator {
  const protocol = reference.slice(0, reference.indexOf(':') + 1);
  if (protocol === 'npm:') return berryNpm(reference);
  if (protocol === 'patch:') return berryPatch(reference);
  return { kind: berryKind(protocol, reference), source: reference, version: null };
}

function berryEntry(key: string, entry: JsonObject): RawEntry {
  const resolution = str(own(entry, 'resolution')) ?? unreadable(key);
  const { name, range } = splitDescriptor(resolution) ?? unreadable(resolution);
  const locator = berryReference(range);
  return {
    name,
    version: locator.version ?? str(own(entry, 'version')) ?? unreadable(key),
    kind: locator.kind,
    source: locator.source,
    integrity: str(own(entry, 'checksum')),
  };
}

/**
 * Yarn Berry: YAML with every scalar a string, as Berry reads it; each entry from its
 * `resolution`, its `checksum` as integrity; dependents from `dependencies`.
 */
function readYarnBerry(source: string): LockEntry[] {
  const lock = objectAt(parseYaml(source, { schema: 'failsafe' }), 'yarn.lock');
  objectAt(own(lock, '__metadata'), '__metadata');
  const entries: RawEntry[] = [];
  const edges: Edge[] = [];
  for (const [key, value] of Object.entries(lock)) {
    if (key === '__metadata') continue;
    const entry = berryEntry(key, objectAt(value, key));
    entries.push(entry);
    edges.push({ from: entry.name, to: dependencyNames(value, 'dependencies') });
  }
  return withDependents(entries, edges);
}

/** As Yarn decides it: a `# yarn lockfile v1` line among the leading comment lines. */
function isYarnClassic(source: string): boolean {
  for (const line of source.split(LINE_BREAK, 64)) {
    if (!line.startsWith('#')) return false;
    if (/^#\s+yarn\s+lockfile\s+v1$/i.test(line)) return true;
  }
  return false;
}

/** `yarn.lock`: classic (`# yarn lockfile v1`) by a line parser, Berry (`__metadata`) as YAML. */
export function readYarnLock(text: string): LockEntry[] {
  const source = stripBom(text);
  return isYarnClassic(source) ? readYarnClassic(source) : readYarnBerry(source);
}

// ---------------------------------------------------------------------------------------------
// The check

/** The public registries of npm, pnpm and Yarn. */
const JS_PUBLIC_REGISTRIES = ['https://registry.npmjs.org', 'https://registry.yarnpkg.com'];

const READERS: ReadonlyMap<string, (text: string) => LockEntry[]> = new Map([
  ['package-lock.json', readNpmLock],
  ['npm-shrinkwrap.json', readNpmLock],
  ['pnpm-lock.yaml', readPnpmLock],
  ['yarn.lock', readYarnLock],
]);

function readBoth(
  read: (text: string) => LockEntry[],
  change: FixFileChange,
): [LockEntry[], LockEntry[]] | null {
  try {
    return [read(change.base), read(change.next)];
  } catch {
    return null;
  }
}

/**
 * B1 for a JS lockfile: both sides are read (`unparsable` when either cannot be), every new entry
 * passes {@link checkLockEntries} (the npm and Yarn public registries allowed; integrity required
 * when a base registry entry has one), and the package's versions reach their targets in this
 * lockfile (`below_target`).
 */
export function checkJsLockfile(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const read = READERS.get(change.path.slice(change.path.lastIndexOf('/') + 1));
  if (read === undefined) return fixRefused('other_change', change.path);
  const both = readBoth(read, change);
  if (both === null) return fixRefused('unparsable', change.path);
  const [base, next] = both;
  const integrityRequired = base.some((e) => e.kind === 'registry' && (e.integrity ?? '') !== '');
  const options = { lockfile: change.path, publicHosts: JS_PUBLIC_REGISTRIES, integrityRequired };
  const entries = checkLockEntries(base, next, { ...ctx, ...options });
  if (!entries.ok) return entries;
  if (lockfileBelowTarget(base, next, ctx, change.path)) {
    return fixRefused('below_target', change.path);
  }
  return FIX_CHECK_OK;
}
