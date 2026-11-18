/**
 * B1 for Python (spec §12): uv and Poetry. `pyproject.toml` may change the specifier of the
 * package's requirement, add or change its uv override, and change (or, in the main table, add)
 * its Poetry constraint; everything else must stay. `uv.lock` and `poetry.lock` are read into
 * {@link LockEntry} lists with PEP 503 names and checked like the JS lockfiles, with PyPI as the
 * public registry and an archive-name rule (Ruling T4a): a file counts as the registry's only when
 * its name is the entry's own name and version.
 */
import { parse as parseToml } from 'smol-toml';
import { compareVersions } from '../versions';
import { parsePep440 } from '../versions/pep440';
import {
  checkLockEntries,
  lockfileBelowTarget,
  newLockEntries,
  sourceOrigin,
} from './lock-entries';
import {
  objectAt,
  readBoth,
  unreadable,
  withDependents,
  type RawEntry,
  type ReadLock,
} from './lock-read';
import {
  FIX_CHECK_OK,
  fixRefused,
  type FixCheckContext,
  type FixCheckResult,
  type FixFileChange,
  type FixRule,
  type LockEntry,
  type LockEntryKind,
} from './types';
import {
  at,
  isObject,
  own,
  parseUrl,
  pruneCreated,
  sameValue,
  setOwn,
  str,
  type JsonObject,
} from './values';

/** PEP 503: lower case, each run of `-`, `_` and `.` one `-`. */
export function normalizePythonName(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase();
}

/**
 * A TOML document (smol-toml): tables with no prototype, `__proto__` and `constructor` kept as own
 * keys, a BOM skipped, nesting limited to 1 000 levels. Throws on a file that is not TOML.
 */
export function readPyproject(text: string): Record<string, unknown> {
  return parseToml(text) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------------------------
// PEP 508 requirements

interface Requirement {
  name: string;
  /** The extras, normalised, sorted and joined by `,`. */
  extras: string;
  /** The version specifier as written (parentheses included); empty when there is none. */
  spec: string;
  /** The URL of a direct reference (`name @ url`); null otherwise. */
  url: string | null;
  marker: string;
}

const NAME_CHARS = /^[A-Za-z\d._-]+/;
const ALPHANUMERIC = /^[A-Za-z\d]$/;

/**
 * Task 4 fix round 1 (I1): PEP 508's white space is space and tab. Any other (a Unicode space,
 * NBSP, U+FEFF, a line break) makes a requirement or constraint unreadable, so no tool can read
 * it differently from this check.
 */
const NOT_PEP508_SPACE = /[^\P{White_Space} \t]|[^\S \t]/u;

function normalizeExtras(text: string): string {
  return text
    .split(',')
    .map((extra) => extra.trim())
    .filter((extra) => extra !== '')
    .map(normalizePythonName)
    .sort((a, b) => (a < b ? -1 : 1))
    .join(',');
}

/** `name [extras] (specifier | @ url) ; marker`; null without a valid name or with a bad `[`. */
function parseRequirement(text: string): Requirement | null {
  if (NOT_PEP508_SPACE.test(text)) return null;
  const s = text.trim();
  const name = NAME_CHARS.exec(s)?.[0];
  if (name === undefined || !ALPHANUMERIC.test(name.charAt(0))) return null;
  if (!ALPHANUMERIC.test(name.charAt(name.length - 1))) return null;
  let rest = s.slice(name.length).trimStart();
  let extras = '';
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close < 0) return null;
    extras = normalizeExtras(rest.slice(1, close));
    rest = rest.slice(close + 1).trimStart();
  }
  const semicolon = rest.indexOf(';');
  const main = (semicolon < 0 ? rest : rest.slice(0, semicolon)).trim();
  const marker = semicolon < 0 ? '' : rest.slice(semicolon + 1).trim();
  if (main.startsWith('@')) return { name, extras, spec: '', url: main.slice(1).trim(), marker };
  return { name, extras, spec: main, url: null, marker };
}

const CLAUSE = /^(~=|==|!=|<=|>=|<|>)\s*(\S+)$/;

/** One clause: an operator (not `===`) and a PEP 440 version, `.*` after `==` or `!=`. */
function isPlainClause(clause: string): boolean {
  const match = CLAUSE.exec(clause);
  const operator = match?.[1];
  const version = match?.[2];
  if (operator === undefined || version === undefined || version.startsWith('=')) return false;
  const wildcard = (operator === '==' || operator === '!=') && version.endsWith('.*');
  return parsePep440(wildcard ? version.slice(0, -2) : version) !== null;
}

/** A plain PEP 440 specifier: one or more clauses, optionally in parentheses; not empty. */
function isPlainSpecifier(spec: string): boolean {
  let s = spec.trim();
  if (s.startsWith('(') && s.endsWith(')')) s = s.slice(1, -1).trim();
  return s !== '' && s.split(',').every((clause) => isPlainClause(clause.trim()));
}

/** A requirement string of the package (by its PEP 503 name). */
function namesPackage(entry: unknown, pkg: string): boolean {
  const requirement = typeof entry === 'string' ? parseRequirement(entry) : null;
  return requirement !== null && normalizePythonName(requirement.name) === pkg;
}

// ---------------------------------------------------------------------------------------------
// pyproject.toml

/** What one changed entry of a requirement list is: a rule, allowed (`restore`), or not ours. */
type EntryVerdict = FixRule | 'restore' | 'leave';

/** The package's requirement with only its specifier changed, to a plain one. */
function requirementChange(before: unknown, after: unknown, pkg: string): EntryVerdict {
  if (typeof before !== 'string' || typeof after !== 'string' || before === after) return 'leave';
  const old = parseRequirement(before);
  if (old === null || normalizePythonName(old.name) !== pkg) return 'leave';
  const now = parseRequirement(after);
  if (now !== null && normalizePythonName(now.name) !== pkg) return 'leave';
  if (now === null || now.url !== null) return 'bad_spec';
  if (now.extras !== old.extras || now.marker !== old.marker) return 'other_change';
  return isPlainSpecifier(now.spec) ? 'restore' : 'bad_spec';
}

function requirementNames(list: readonly unknown[]): Set<string> {
  const names = new Set<string>();
  for (const entry of list) {
    const requirement = typeof entry === 'string' ? parseRequirement(entry) : null;
    if (requirement !== null) names.add(normalizePythonName(requirement.name));
  }
  return names;
}

/** A list that grew: a requirement of a package the list did not name is `new_dependency`. */
function addedRequirementRule(before: readonly unknown[], after: readonly unknown[], pkg: string) {
  const known = requirementNames(before);
  for (const name of requirementNames(after)) {
    if (name !== pkg && !known.has(name)) return 'new_dependency';
  }
  return null;
}

/**
 * One requirement list: the package's changed specifiers checked and put back (paired by
 * position); a list that grew is checked for new packages. The rest is left for the comparison.
 */
function requirementListRule(before: unknown, after: unknown, pkg: string): FixRule | null {
  if (!Array.isArray(after)) return null;
  const old: readonly unknown[] = before === undefined ? [] : (before as unknown[]);
  if (!Array.isArray(old)) return null;
  if (old.length !== after.length) return addedRequirementRule(old, after, pkg);
  for (const [i, entry] of after.entries()) {
    const verdict = requirementChange(old[i], entry, pkg);
    if (verdict === 'restore') after[i] = old[i];
    else if (verdict !== 'leave') return verdict;
  }
  return null;
}

/** Each list of a table of lists (`project.optional-dependencies`, `dependency-groups`). */
function tableLists(base: JsonObject, next: JsonObject, path: string[]): [unknown, unknown][] {
  const after = at(next, path);
  if (!isObject(after)) return [];
  const before = at(base, path);
  return Object.keys(after).map((key) => [
    isObject(before) ? own(before, key) : undefined,
    own(after, key),
  ]);
}

/** PEP 621 and PEP 735: `project.dependencies`, its optional groups, and dependency groups. */
function projectRequirementsRule(base: JsonObject, next: JsonObject, pkg: string): FixRule | null {
  const lists: [unknown, unknown][] = [
    [at(base, ['project', 'dependencies']), at(next, ['project', 'dependencies'])],
    ...tableLists(base, next, ['project', 'optional-dependencies']),
    ...tableLists(base, next, ['dependency-groups']),
  ];
  for (const [before, after] of lists) {
    const rule = requirementListRule(before, after, pkg);
    if (rule !== null) return rule;
  }
  return null;
}

const UV_PATH = ['tool', 'uv'];
const OVERRIDES = 'override-dependencies';

/** A requirement's extras and marker, as one key. */
function shapeOf({ extras, marker }: Pick<Requirement, 'extras' | 'marker'>): string {
  return JSON.stringify([extras, marker]);
}

/**
 * Fix round 1, M1: the extras and markers a new or changed override of the package may have:
 * those of the base's overrides of it, or none when the base has none (a never-true marker would
 * drop the package).
 */
function overrideShapes(before: readonly unknown[], pkg: string): Set<string> {
  const shapes = new Set<string>();
  for (const entry of before) {
    const requirement = typeof entry === 'string' ? parseRequirement(entry) : null;
    if (requirement !== null && normalizePythonName(requirement.name) === pkg) {
      shapes.add(shapeOf(requirement));
    }
  }
  if (shapes.size === 0) shapes.add(shapeOf({ extras: '', marker: '' }));
  return shapes;
}

/** A new or changed override of the package: no URL and plain (`bad_spec`), a known shape. */
function overrideRule(entry: unknown, shapes: ReadonlySet<string>): FixRule | null {
  const requirement = typeof entry === 'string' ? parseRequirement(entry) : null;
  if (requirement === null || requirement.url !== null) return 'bad_spec';
  if (!shapes.has(shapeOf(requirement))) return 'other_change';
  return isPlainSpecifier(requirement.spec) ? null : 'bad_spec';
}

/**
 * `tool.uv.override-dependencies`: the package's entries may be added or changed, each plain
 * (`bad_spec`) and with the extras and marker of the base's (none when the base has none,
 * `other_change`, M1); they are taken out of both sides, the array and tables dropped when the
 * change created them for those entries alone.
 */
function uvOverridesRule(base: JsonObject, next: JsonObject, pkg: string): FixRule | null {
  const uv = at(next, UV_PATH);
  const after = isObject(uv) ? own(uv, OVERRIDES) : undefined;
  if (!isObject(uv) || !Array.isArray(after)) return null;
  const baseUv = at(base, UV_PATH);
  const before = isObject(baseUv) ? own(baseUv, OVERRIDES) : undefined;
  const oldList: readonly unknown[] = Array.isArray(before) ? before : [];
  const old = new Set<unknown>(oldList);
  const shapes = overrideShapes(oldList, pkg);
  for (const entry of after) {
    if (!namesPackage(entry, pkg) || old.has(entry)) continue;
    const rule = overrideRule(entry, shapes);
    if (rule !== null) return rule;
  }
  const rest = after.filter((entry) => !namesPackage(entry, pkg));
  if (isObject(baseUv) && Array.isArray(before)) {
    setOwn(uv, OVERRIDES, rest);
    setOwn(
      baseUv,
      OVERRIDES,
      before.filter((entry) => !namesPackage(entry, pkg)),
    );
  } else if (rest.length === 0) {
    Reflect.deleteProperty(uv, OVERRIDES);
    pruneCreated(base, next, UV_PATH);
  }
  return null;
}

/** What a Poetry dependency table may not hold: a source other than the registry. */
const POETRY_SOURCES = ['git', 'path', 'url', 'file'];
const POETRY_OPERATOR = /^(?:\^|~=?|[<>]=?|[=!]=|=)$/;
const POETRY_CLAUSE = /^(?:\^|~=?|[<>]=?|[=!]=|=)?(?:\*|\d[\w.*+!-]*)$/;

/** A Poetry version constraint: clauses split by `,`, `||` or spaces, each an operator and version. */
function isPlainConstraint(text: string): boolean {
  if (NOT_PEP508_SPACE.test(text)) return false;
  const tokens = text.replaceAll('||', ',').replaceAll(',', ' ').trim().split(/\s+/);
  const clauses: string[] = [];
  for (const token of tokens) {
    const last = clauses.at(-1);
    if (last !== undefined && POETRY_OPERATOR.test(last))
      clauses[clauses.length - 1] = last + token;
    else clauses.push(token);
  }
  return clauses.every((clause) => POETRY_CLAUSE.test(clause));
}

function constraintRule(value: unknown): FixRule | null {
  return typeof value === 'string' && isPlainConstraint(value) ? null : 'bad_spec';
}

function hasPoetrySource(value: unknown): boolean {
  return isObject(value) && POETRY_SOURCES.some((key) => Object.hasOwn(value, key));
}

function withoutVersion(table: JsonObject): JsonObject {
  const copy: JsonObject = { ...table };
  Reflect.deleteProperty(copy, 'version');
  return copy;
}

/** A changed constraint: a plain string for a string, or a table where only `version` differs. */
function changedConstraintRule(before: unknown, after: unknown): FixRule | null {
  if (sameValue(before, after)) return null;
  if (hasPoetrySource(after)) return 'bad_spec';
  if (typeof after === 'string')
    return typeof before === 'string' ? constraintRule(after) : 'other_change';
  if (!isObject(after) || !isObject(before)) return 'other_change';
  if (!sameValue(withoutVersion(before), withoutVersion(after))) return 'other_change';
  return constraintRule(own(after, 'version'));
}

/** An added constraint: a plain string, or a table of `version` alone. */
function addedConstraintRule(value: unknown): FixRule | null {
  if (typeof value === 'string') return constraintRule(value);
  if (hasPoetrySource(value)) return 'bad_spec';
  if (!isObject(value) || Object.keys(value).some((key) => key !== 'version'))
    return 'other_change';
  return constraintRule(own(value, 'version'));
}

function poetryKeys(table: JsonObject, pkg: string): string[] {
  return Object.keys(table).filter((key) => normalizePythonName(key) === pkg);
}

/** A key the table did not have, for another package: `new_dependency`. */
function newPoetryKeyRule(
  before: JsonObject | null,
  after: JsonObject,
  pkg: string,
): FixRule | null {
  const added = Object.keys(after).filter((key) => before === null || !Object.hasOwn(before, key));
  return added.some((key) => normalizePythonName(key) !== pkg) ? 'new_dependency' : null;
}

/**
 * One Poetry dependency table: the package's key (one, by its PEP 503 name) changed, or, where
 * `mayAdd`, added when the table had none; checked, then put back or taken out (with the tables
 * created for it).
 */
function poetryTableRule(
  base: JsonObject,
  next: JsonObject,
  path: string[],
  pkg: string,
  mayAdd: boolean,
): FixRule | null {
  const after = at(next, path);
  if (!isObject(after)) return null;
  const beforeValue = at(base, path);
  const before = isObject(beforeValue) ? beforeValue : null;
  const added = newPoetryKeyRule(before, after, pkg);
  if (added !== null) return added;
  const keys = poetryKeys(after, pkg);
  const [key] = keys;
  if (keys.length !== 1 || key === undefined) return null;
  if (before !== null && Object.hasOwn(before, key)) {
    const rule = changedConstraintRule(own(before, key), own(after, key));
    if (rule === null) setOwn(after, key, own(before, key));
    return rule;
  }
  if (!mayAdd || (before !== null && poetryKeys(before, pkg).length > 0)) return null;
  const rule = addedConstraintRule(own(after, key));
  if (rule !== null) return rule;
  Reflect.deleteProperty(after, key);
  pruneCreated(base, next, path);
  return null;
}

/** `tool.poetry.dependencies` (changed or added) and `tool.poetry.group.*.dependencies` (changed). */
function poetryRule(base: JsonObject, next: JsonObject, pkg: string): FixRule | null {
  const main = poetryTableRule(base, next, ['tool', 'poetry', 'dependencies'], pkg, true);
  if (main !== null) return main;
  const groups = at(next, ['tool', 'poetry', 'group']);
  if (!isObject(groups)) return null;
  for (const group of Object.keys(groups)) {
    const path = ['tool', 'poetry', 'group', group, 'dependencies'];
    const rule = poetryTableRule(base, next, path, pkg, false);
    if (rule !== null) return rule;
  }
  return null;
}

const PYPROJECT_STEPS = [projectRequirementsRule, uvOverridesRule, poetryRule];

function pyprojectRule(base: JsonObject, next: JsonObject, pkg: string): FixRule | null {
  for (const step of PYPROJECT_STEPS) {
    const rule = step(base, next, pkg);
    if (rule !== null) return rule;
  }
  return sameValue(base, next) ? null : 'other_change';
}

function readTomlObject(text: string): JsonObject | null {
  try {
    const value = readPyproject(text);
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * B1 for `pyproject.toml` (Ruling F27: each part a named step). Allowed: the specifier of the
 * package's requirement in `project.dependencies`, `project.optional-dependencies.*` and
 * `dependency-groups.*` (same name, extras and markers); an added or changed entry for it in
 * `tool.uv.override-dependencies`; its constraint in `tool.poetry.dependencies` or
 * `tool.poetry.group.*.dependencies` changed, or added to `tool.poetry.dependencies` (a string,
 * or a table of `version` alone; where it is changed, only `version` may differ). A direct
 * reference, a path, git or url table, or a specifier that is not plain is `bad_spec`; a
 * requirement of another package `new_dependency`; anything else (`build-system` included)
 * `other_change`. Names compare by PEP 503.
 */
export function checkPyproject(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const base = readTomlObject(change.base);
  const next = readTomlObject(change.next);
  if (base === null || next === null) return fixRefused('unparsable', change.path);
  const rule = pyprojectRule(base, next, normalizePythonName(ctx.packageName));
  return rule === null ? FIX_CHECK_OK : fixRefused(rule, change.path);
}

// ---------------------------------------------------------------------------------------------
// Archive names (Ruling T4a)

const SDIST_EXTENSIONS = ['.tar.gz', '.zip', '.tar.bz2', '.tgz'];

/** The name and version a wheel or sdist file name gives; null for any other file. */
function archiveOwner(file: string): { name: string; version: string } | null {
  if (file.endsWith('.whl')) {
    const parts = file.slice(0, -'.whl'.length).split('-');
    const [name, version] = parts;
    const wheel = parts.length === 5 || parts.length === 6;
    return wheel && name !== undefined && version !== undefined ? { name, version } : null;
  }
  const extension = SDIST_EXTENSIONS.find((ext) => file.endsWith(ext));
  if (extension === undefined) return null;
  const stem = file.slice(0, -extension.length);
  const dash = stem.lastIndexOf('-');
  return dash <= 0 ? null : { name: stem.slice(0, dash), version: stem.slice(dash + 1) };
}

/** The file name of a location: a URL's last path segment, decoded, or a path's last part. */
function fileOf(location: string | null): string | null {
  if (location === null) return null;
  const path = parseUrl(location)?.pathname ?? location;
  try {
    const file = decodeURIComponent(path.slice(path.lastIndexOf('/') + 1));
    return /[/\\]/.test(file) ? null : file;
  } catch {
    return null;
  }
}

/**
 * Ruling T4a: a registry file is the registry's (`registry`) only when its name belongs to the
 * entry's own name (PEP 503) and version (PEP 440 equal); any other file is a `tarball`.
 */
function archiveKind(file: string | null, name: string, version: string): LockEntryKind {
  const owner = file === null ? null : archiveOwner(file);
  const belongs =
    owner !== null &&
    normalizePythonName(owner.name) === name &&
    compareVersions('pep440', owner.version, version) === 0;
  return belongs ? 'registry' : 'tarball';
}

// ---------------------------------------------------------------------------------------------
// uv.lock and poetry.lock

function arrayAt(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) unreadable(what);
  return value;
}

function hashOf(value: unknown): string | null {
  const hash = str(value);
  return hash === null || hash === '' ? null : hash;
}

function parseLockToml(text: string): JsonObject {
  return objectAt(readPyproject(text), 'lockfile');
}

interface Artifact {
  location: string | null;
  hash: string | null;
}

type PackageBase = Pick<RawEntry, 'name' | 'version' | 'dependencies'>;

/**
 * A registry package: one entry per file (Ruling T4a decides its kind), and one for its index,
 * whose integrity is the files' hashes (null without any), so the index's host is checked too.
 */
function registryEntries(
  base: PackageBase,
  index: string | null,
  artifacts: readonly Artifact[],
): RawEntry[] {
  const files: RawEntry[] = artifacts.map(({ location, hash }) => ({
    ...base,
    source: location,
    kind: archiveKind(fileOf(location), base.name, base.version),
    integrity: hash,
  }));
  const hashes = artifacts.flatMap(({ hash }) => (hash === null ? [] : [hash]));
  const integrity = hashes.length === 0 ? null : hashes.sort((a, b) => (a < b ? -1 : 1)).join(' ');
  return [...files, { ...base, source: index, kind: 'registry', integrity }];
}

const UV_KINDS: ReadonlyMap<string, LockEntryKind> = new Map([
  ['registry', 'registry'],
  ['git', 'git'],
  ['path', 'file'],
  ['directory', 'path'],
  ['editable', 'path'],
  ['virtual', 'path'],
  ['url', 'tarball'],
]);

/** A uv `source` table of exactly one known key with a string value; else kind `other`. */
function uvSource(pkg: JsonObject): Pick<RawEntry, 'kind' | 'source'> {
  const table = objectAt(own(pkg, 'source'), 'a uv package source');
  const keys = Object.keys(table);
  const [key] = keys;
  const kind = keys.length === 1 && key !== undefined ? UV_KINDS.get(key) : undefined;
  const source = key === undefined ? null : str(own(table, key));
  return kind === undefined || source === null ? { kind: 'other', source: null } : { kind, source };
}

/** The names of a uv dependency list (`[{ name = "x" }, …]`), normalised. */
function uvDependencyNames(list: unknown): string[] {
  return arrayAt(list, 'uv dependencies').map((dependency) => {
    const name = str(own(objectAt(dependency, 'a uv dependency'), 'name'));
    return name === null ? unreadable('a uv dependency without a name') : normalizePythonName(name);
  });
}

/** `dependencies`, and the lists of `optional-dependencies` and `dev-dependencies`. */
function uvDependencies(pkg: JsonObject): string[] {
  const lists: unknown[] = [];
  const direct = own(pkg, 'dependencies');
  if (direct !== undefined) lists.push(direct);
  for (const table of ['optional-dependencies', 'dev-dependencies']) {
    const groups = own(pkg, table);
    if (groups !== undefined) lists.push(...Object.values(objectAt(groups, table)));
  }
  return lists.flatMap(uvDependencyNames);
}

function uvArtifacts(pkg: JsonObject): Artifact[] {
  const sdist = own(pkg, 'sdist');
  const wheels = own(pkg, 'wheels');
  const all = [
    ...(sdist === undefined ? [] : [sdist]),
    ...(wheels === undefined ? [] : arrayAt(wheels, 'wheels')),
  ];
  return all.map((value) => {
    const artifact = objectAt(value, 'a uv artifact');
    const location = str(own(artifact, 'url')) ?? str(own(artifact, 'path'));
    return { location, hash: hashOf(own(artifact, 'hash')) };
  });
}

function uvEntries(value: unknown): RawEntry[] {
  const pkg = objectAt(value, 'a uv package');
  const name = str(own(pkg, 'name')) ?? unreadable('a uv package without a name');
  const base: PackageBase = {
    name: normalizePythonName(name),
    version: str(own(pkg, 'version')) ?? '',
    dependencies: uvDependencies(pkg),
  };
  const { kind, source } = uvSource(pkg);
  const artifacts = uvArtifacts(pkg);
  if (kind === 'registry') return registryEntries(base, source, artifacts);
  return [{ ...base, kind, source, integrity: artifacts[0]?.hash ?? null }];
}

function lockFormat(manager: string, version: unknown): string {
  return `${manager}-${typeof version === 'number' || typeof version === 'string' ? version : 'none'}`;
}

function parseUvLock(text: string): ReadLock {
  const lock = parseLockToml(text);
  const packages = own(lock, 'package');
  const list = packages === undefined ? [] : arrayAt(packages, 'package');
  return {
    format: lockFormat('uv', own(lock, 'version')),
    entries: withDependents(list.flatMap(uvEntries)),
  };
}

/**
 * `uv.lock`: a `source.registry` package is one `registry` entry per sdist and wheel (its URL the
 * source, its `hash` the integrity, the kind by Ruling T4a) and one for its index URL; `git`,
 * `path` (a file), `directory`, `editable`, `virtual` and `url` give their kinds. Names are PEP 503
 * normalised; dependencies come from `dependencies`, `optional-dependencies` and
 * `dev-dependencies`. Throws on a file it cannot read.
 */
export function readUvLock(text: string): LockEntry[] {
  return parseUvLock(text).entries;
}

const POETRY_KINDS: ReadonlyMap<string, LockEntryKind> = new Map([
  ['legacy', 'registry'],
  ['git', 'git'],
  ['file', 'file'],
  ['directory', 'path'],
  ['url', 'tarball'],
]);

/**
 * What picks the code of a non-registry Poetry source besides its URL: Poetry clones
 * `resolved_reference` (else `reference`) and builds `subdirectory` (task 4 fix round 1, C1).
 */
const SOURCE_FIELDS = ['reference', 'resolved_reference', 'subdirectory'];

/** Marks the reference folded into a legacy source; Poetry picks the repository by it (I2). */
const LEGACY_REFERENCE = '#poetry-reference=';

function fieldOf(table: JsonObject, name: string): string {
  return encodeURIComponent(str(own(table, name)) ?? '');
}

/**
 * No `[package.source]`: PyPI, no source. A legacy source is its `url` with its `reference`
 * folded in (a url that holds `#` already, or none, is `other`). Any other type's source is its
 * `url` with `reference`, `resolved_reference` and `subdirectory` folded in, so moving any of them
 * makes a new entry (C1); an unknown type is `other`.
 */
function poetrySource(pkg: JsonObject): Pick<RawEntry, 'kind' | 'source'> {
  const value = own(pkg, 'source');
  if (value === undefined) return { kind: 'registry', source: null };
  const table = objectAt(value, 'a poetry package source');
  const url = str(own(table, 'url'));
  const kind = POETRY_KINDS.get(str(own(table, 'type')) ?? '') ?? 'other';
  if (url === null) return { kind: 'other', source: null };
  if (kind === 'registry') {
    if (url.includes('#')) return { kind: 'other', source: url };
    return { kind, source: `${url}${LEGACY_REFERENCE}${fieldOf(table, 'reference')}` };
  }
  const fields = SOURCE_FIELDS.map((name) => `${name}=${fieldOf(table, name)}`).join('&');
  return { kind, source: `${url}#${fields}` };
}

/**
 * The origin key of a Python lockfile source: its `scheme://host`, or, for a Poetry legacy
 * source, the whole `(url, reference)` pair, since Poetry fetches from the source its reference
 * names (task 4 fix round 1, I2; Ruling T4f).
 */
function pythonOrigin(source: string): string | null {
  const origin = sourceOrigin(source);
  return origin !== null && source.includes(LEGACY_REFERENCE) ? source : origin;
}

function poetryFiles(value: unknown): { file: string | null; hash: string | null }[] {
  if (value === undefined) return [];
  return arrayAt(value, 'poetry files').map((item) => {
    const file = objectAt(item, 'a poetry file');
    return { file: str(own(file, 'file')), hash: hashOf(own(file, 'hash')) };
  });
}

function poetryEntries(value: unknown, legacyFiles: JsonObject): RawEntry[] {
  const pkg = objectAt(value, 'a poetry package');
  const name = str(own(pkg, 'name')) ?? unreadable('a poetry package without a name');
  const dependencies = own(pkg, 'dependencies');
  const base: PackageBase = {
    name: normalizePythonName(name),
    version: str(own(pkg, 'version')) ?? '',
    dependencies:
      dependencies === undefined
        ? []
        : Object.keys(objectAt(dependencies, 'poetry dependencies')).map(normalizePythonName),
  };
  const files = poetryFiles(own(pkg, 'files') ?? own(legacyFiles, name));
  const { kind, source } = poetrySource(pkg);
  if (kind !== 'registry' || files.length === 0) {
    return [{ ...base, kind, source, integrity: files[0]?.hash ?? null }];
  }
  return files.map(({ file, hash }) => ({
    ...base,
    source,
    kind: archiveKind(file, base.name, base.version),
    integrity: hash,
  }));
}

function parsePoetryLock(text: string): ReadLock {
  const lock = parseLockToml(text);
  const metadata = own(lock, 'metadata');
  const meta = metadata === undefined ? {} : objectAt(metadata, 'metadata');
  const legacy = own(meta, 'files');
  const legacyFiles = legacy === undefined ? {} : objectAt(legacy, 'metadata.files');
  const packages = own(lock, 'package');
  const list = packages === undefined ? [] : arrayAt(packages, 'package');
  const raw = list.flatMap((pkg) => poetryEntries(pkg, legacyFiles));
  return { format: lockFormat('poetry', own(meta, 'lock-version')), entries: withDependents(raw) };
}

/**
 * `poetry.lock`: one entry per `files[]` item (Poetry 1.x: `[metadata.files]`), its `hash` the
 * integrity; without `[package.source]` a PyPI `registry` entry (no source), the kind by Ruling
 * T4a; `type` `legacy` a `registry` entry with its `url` as source; `git`, `file`, `directory` and
 * `url` give their kinds. Names are PEP 503 normalised; dependencies come from
 * `[package.dependencies]`. Throws on a file it cannot read.
 */
export function readPoetryLock(text: string): LockEntry[] {
  return parsePoetryLock(text).entries;
}

/** PyPI: the index and the file host. */
const PYTHON_PUBLIC_HOSTS = ['https://pypi.org', 'https://files.pythonhosted.org'];

const PYTHON_READERS: ReadonlyMap<string, (text: string) => ReadLock> = new Map([
  ['uv.lock', parseUvLock],
  ['poetry.lock', parsePoetryLock],
]);

function readerFor(path: string): ((text: string) => ReadLock) | undefined {
  return PYTHON_READERS.get(path.slice(path.lastIndexOf('/') + 1));
}

/**
 * Ruling T3i: the packages a Python lockfile change adds, once each by slot, name and version,
 * for the MR body; null for a file that is not a Python lockfile or cannot be read in one format.
 */
export function pythonLockfileAdditions(change: FixFileChange): LockEntry[] | null {
  const read = readerFor(change.path);
  const both = read === undefined ? null : readBoth(read, change);
  if (both === null) return null;
  const seen = new Set<string>();
  return newLockEntries(both[0], both[1]).filter((entry) => {
    const key = JSON.stringify([entry.slot ?? null, entry.name, entry.version]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * B1 for `uv.lock` and `poetry.lock`: both sides read in one format (`unparsable` otherwise);
 * every new entry passes {@link checkLockEntries} with PyPI as the public registry, integrity
 * required, and new entries reachable from the package; then the package's versions reach their
 * targets in this lockfile (`below_target`). Names compare by PEP 503.
 */
export function checkPythonLock(change: FixFileChange, ctx: FixCheckContext): FixCheckResult {
  const read = readerFor(change.path);
  if (read === undefined) return fixRefused('other_change', change.path);
  const both = readBoth(read, change);
  if (both === null) return fixRefused('unparsable', change.path);
  const [base, next] = both;
  const named = { ...ctx, packageName: normalizePythonName(ctx.packageName) };
  const entries = checkLockEntries(base, next, {
    ...named,
    lockfile: change.path,
    publicHosts: PYTHON_PUBLIC_HOSTS,
    integrityRequired: true,
    reachableOnly: true,
    originOf: pythonOrigin,
  });
  if (!entries.ok) return entries;
  if (lockfileBelowTarget(base, next, named, change.path)) {
    return fixRefused('below_target', change.path);
  }
  return FIX_CHECK_OK;
}
