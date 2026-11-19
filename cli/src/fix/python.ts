import { isDeepStrictEqual } from 'node:util';
import picomatch from 'picomatch';
import {
  compareVersions,
  FIX_MAX_DEPENDENTS,
  greatestVersion,
  normalizePythonName,
  readPoetryLock,
  readPyproject,
  readUvLock,
  releaseLine,
  versionParses,
  type FixClaimItem,
  type FixLockfile,
  type FixTarget,
  type LockEntry,
} from '@qualor/shared/fix';
import type {
  AppliedFix,
  FixAdapter,
  FixPlan,
  FixStop,
  FixWorkspace,
  InstalledAt,
} from './adapter';
import {
  replaceInSection,
  setTomlArrayEntry,
  setTomlKey,
  oneLine,
  tomlSectionName,
  tomlValue,
  type TomlSpan,
} from './edit/toml';
import {
  absolute,
  basename,
  dirOf,
  isRegularFile,
  isStop,
  notRegular,
  readText,
  timeLeft,
  unsupported,
  writeText,
} from './files';
import { toolFailure, type ToolResult } from './runner';

/**
 * The Python family (spec §6.5, B3, B7, R25, R27): uv and Poetry. The folder of each `uv.lock` or
 * `poetry.lock` that resolves the package to a vulnerable version is a project; its
 * `pyproject.toml` is edited as text (layout, comments and line endings kept), then the project's
 * own tool regenerates the lockfile.
 *
 * - **Direct** (a requirement or constraint for the package in `project.dependencies`, an optional
 *   group, a dependency group, or a Poetry table): its version is raised to the target, its
 *   operator, extras, marker and upper bound kept (`pep508WithTarget`, `poetryConstraintWithTarget`).
 *   A uv workspace's members (the root's `tool.uv.workspace`) are searched too.
 * - **Transitive**: uv gets `qf>=<target>,<<next release line>` in `tool.uv.override-dependencies`
 *   (an existing override for the package is raised instead); Poetry, which has no overrides, gets
 *   `qf = "^<target>"` in `[tool.poetry.dependencies]` with a one-line comment naming the
 *   vulnerabilities and dependents. Both ignore the lockfile's other versions of the package, so a
 *   transitive package on several release lines ends `no_fix several_lines` (B3).
 * - **Refused before any tool runs** (`manifest_unsupported`): a requirement Qualor does not
 *   rewrite (a direct reference, `!=`, a range with no lower bound, `===`), a source for the package
 *   in `tool.uv.sources`, `tool.uv.dev-dependencies` or `tool.poetry.dev-dependencies` naming it,
 *   a lockfile without a `pyproject.toml` beside it, both lockfiles in one folder, links.
 * - **Tools:** `uv lock --no-build` with `UV_FROZEN` and `UV_LOCKED` off (the job's values would
 *   stop it writing). `--no-build` (B9, ruling FW1) keeps uv from building a source distribution
 *   to read its metadata, which would run that package's build code: a lock that needs a build
 *   fails as `package_manager`. `poetry lock --no-interaction`, with `--no-update` on Poetry 1.x
 *   (from `poetry --version`, read before any file is written). Poetry has no such switch and may
 *   build a source distribution to read its metadata; the guide states that residual.
 * - **Target lockfile:** each target names the `uv.lock` or `poetry.lock` it changes.
 *
 * Every edit is read back with the full TOML parser and compared with the planned change before it
 * is written, so a layout the text edit misjudged fails closed.
 */

type Doc = Record<string, unknown>;
type Manager = 'uv' | 'poetry';

/** A folder with a lockfile, its `pyproject.toml`, and (uv) the workspace members' ones. */
interface Project {
  /** '' at the repository root, else the folder with a trailing `/`. */
  dir: string;
  lockfile: string;
  manager: Manager;
  pyproject: string;
}

/** What `planProject` decided for a project (R6). */
interface ProjectPlan {
  project: Project;
  relation: 'direct' | 'transitive';
  mechanism: string | null;
}

/** A requirement string of a PEP 508 list that names the package. */
interface Requirement {
  kind: 'requirement';
  file: string;
  /** The TOML section that holds the array. */
  section: string;
  /** Where the string is in the parsed file (the array's path and its index). */
  path: string[];
  text: string;
  /** An entry of `tool.uv.override-dependencies`, not a dependency. */
  override: boolean;
}

/** A Poetry dependency table entry for the package. */
interface PoetryDependency {
  kind: 'poetry';
  file: string;
  /** The dependency table's path (`tool.poetry.dependencies`, a group's). */
  table: string[];
  key: string;
  value: unknown;
}

type Declaration = Requirement | PoetryDependency;

/** One planned change of a parsed file: the value at `path`. */
interface Mod {
  path: readonly string[];
  value: unknown;
}

const PYPROJECT = 'pyproject.toml';
const UV_LOCK = 'uv.lock';
const POETRY_LOCK = 'poetry.lock';
const UV_ENV = { UV_FROZEN: 'false', UV_LOCKED: 'false' };
/** B9, ruling FW1: `uv lock` never builds a source distribution, so no dependency's code runs. */
const UV_LOCK_ARGS = ['lock', '--no-build'];
const OVERRIDES = 'override-dependencies';
const UV_PATH = ['tool', 'uv'];
const POETRY_DEPENDENCIES = ['tool', 'poetry', 'dependencies'];

const isRecord = (v: unknown): v is Doc => typeof v === 'object' && v !== null && !Array.isArray(v);
const keysOf = (v: unknown): string[] => (isRecord(v) ? Object.keys(v) : []);
const where = (dir: string) => (dir === '' ? 'the repository root' : dir);
const clip = (text: string) => (text.length > 200 ? `${text.slice(0, 200)}…` : text);

function getPath(doc: unknown, path: readonly string[]): unknown {
  let cur = doc;
  for (const key of path) {
    if (!isRecord(cur) && !Array.isArray(cur)) return undefined;
    cur = Object.hasOwn(cur, key) ? (cur as Doc)[key] : undefined;
  }
  return cur;
}

/** Sets the value at `path` of a parsed file, creating the tables on the way. */
function setPath(doc: Doc, path: readonly string[], value: unknown): void {
  let cur: Doc = doc;
  for (const key of path.slice(0, -1)) {
    let next = Object.hasOwn(cur, key) ? cur[key] : undefined;
    if (next === undefined) {
      next = Object.create(null) as Doc;
      cur[key] = next;
    }
    if (typeof next !== 'object' || next === null) throw new Error(`${key} is not a table`);
    cur = next as Doc;
  }
  cur[path.at(-1) ?? ''] = value;
}

// ─── Versions and names ─────────────────────────────────────────────────────

const byVersion = (a: string, b: string) => {
  const c = compareVersions('pep440', a, b);
  if (c !== null) return c;
  if (a < b) return -1;
  return a > b ? 1 : 0;
};
const lineOf = (v: string) => releaseLine('pep440', v) ?? v;
const lineName = (line: string) => `${line}.x`;

/** Release lines (`1`, `0.2`) in numeric order. */
function compareLines(a: string, b: string): number {
  const [x, y] = [a.split('.').map(Number), b.split('.').map(Number)];
  const c = (x[0] ?? 0) - (y[0] ?? 0) || (x[1] ?? 0) - (y[1] ?? 0);
  if (Number.isNaN(c) || c !== 0) return Number.isNaN(c) ? byVersion(a, b) : c;
  return 0;
}

function listed(items: readonly string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items.at(-1) ?? ''}`;
}

/** How many release numbers a version has (`1.2.5` is 3). */
function releaseCount(version: string): number {
  const release = /^(?:\d+!)?(\d+(?:\.\d+)*)/.exec(version)?.[1] ?? '';
  return release === '' ? 0 : release.split('.').length;
}

/** The first version of the release line after the one of `target`, or null (`1.2.6` → `2`). */
function nextLine(target: string): string | null {
  const match = /^(?:(\d+)!)?(\d+)(?:\.(\d+))?$/.exec(releaseLine('pep440', target) ?? '');
  if (match === null) return null;
  const [, epoch, major, minor] = match;
  const prefix = epoch === undefined ? '' : `${epoch}!`;
  if (Number(major) === 0 && minor !== undefined) return `${prefix}0.${Number(minor) + 1}`;
  return `${prefix}${Number(major) + 1}`;
}

const REQUIREMENT_NAME = /^\s*([A-Za-z\d](?:[\w.-]*[A-Za-z\d])?)/;

/** The PEP 503 name a requirement string starts with; null for text that is no requirement. */
function requirementName(text: string): string | null {
  const name = REQUIREMENT_NAME.exec(text)?.[1];
  return name === undefined ? null : normalizePythonName(name);
}

// ─── Requirement rewrites ───────────────────────────────────────────────────

/** The name and extras at the start of a requirement. */
const REQUIREMENT_HEAD = /^\s*[A-Za-z\d](?:[\w.-]*[A-Za-z\d])?\s*(?:\[[^\]]*\]\s*)?/;
const OPERATOR = /^(?:~=|==|!=|<=|>=|<|>)/;

interface Clause {
  lead: string;
  op: string;
  gap: string;
  version: string;
  trail: string;
}

/** The whitespace before and after a text, and the text between. */
function padded(text: string): { lead: string; core: string; trail: string } {
  const core = text.trim();
  const lead = text.slice(0, text.length - text.trimStart().length);
  return { lead, core, trail: text.slice(lead.length + core.length) };
}

function parseClause(text: string): Clause | null {
  const { lead, core, trail } = padded(text);
  const op = OPERATOR.exec(core)?.[0];
  if (op === undefined) return null;
  const rest = padded(core.slice(op.length));
  if (rest.core === '' || /\s/.test(rest.core)) return null;
  return { lead, op, gap: rest.lead, version: rest.core, trail };
}

/** A specifier without its parentheses: the text up to and from them, and what they hold. */
function peelParens(spec: string): { open: string; core: string; close: string } | null {
  const text = spec.trim();
  if (text.startsWith('(') !== text.endsWith(')')) return null;
  if (!text.startsWith('(')) return { open: '', core: spec, close: '' };
  const start = spec.indexOf('(') + 1;
  const end = spec.lastIndexOf(')');
  const core = spec.slice(start, end);
  if (end < start || /[()]/.test(core)) return null;
  return { open: spec.slice(0, start), core, close: spec.slice(end) };
}

/** A requirement's name and extras, its version specifier, and its marker (with its `;`). */
function splitRequirement(req: string): { head: string; spec: string; tail: string } | null {
  const head = REQUIREMENT_HEAD.exec(req)?.[0];
  if (head === undefined) return null;
  const rest = req.slice(head.length);
  const semicolon = rest.indexOf(';');
  const spec = semicolon < 0 ? rest : rest.slice(0, semicolon);
  if (spec.includes('@')) return null;
  return { head, spec, tail: semicolon < 0 ? '' : rest.slice(semicolon) };
}

/** Whether a version is allowed by an upper bound clause (`<` or `<=`). */
function belowBound(target: string, bound: Clause): boolean {
  const c = compareVersions('pep440', target, bound.version);
  if (c === null) return false;
  return bound.op === '<' ? c < 0 : c <= 0;
}

/** The one lower bound (`>=`, `==`, `~=`) of the clauses when the rest are upper bounds the target meets. */
function lowerBound(clauses: readonly Clause[], target: string): Clause | null {
  const lowers = clauses.filter((c) => ['>=', '==', '~='].includes(c.op));
  const uppers = clauses.filter((c) => c.op === '<' || c.op === '<=');
  const [lower] = lowers;
  if (lower === undefined || lowers.length !== 1) return null;
  if (lowers.length + uppers.length !== clauses.length) return null;
  if (lower.op === '==' && clauses.length > 1) return null;
  if (!versionParses('pep440', lower.version)) return null;
  if (lower.op === '~=' && releaseCount(lower.version) !== releaseCount(target)) return null;
  const bounded = uppers.every((u) => versionParses('pep440', u.version) && belowBound(target, u));
  return bounded ? lower : null;
}

/**
 * A PEP 508 requirement with its lower bound (`>=`, `==` or `~=`, or the lone version of a
 * parenthesised or comma list) set to `target`: extras, marker, spacing, other upper bounds kept.
 * Null (left to a person) for a requirement with no version, a direct reference, `!=`, `>`,
 * `===`, `==1.2.*`, several lower bounds, an upper bound the target breaks, a `~=` target with
 * another number of release numbers, or a target that is no PEP 440 version.
 */
export function pep508WithTarget(req: string, target: string): string | null {
  if (!versionParses('pep440', target)) return null;
  const parts = splitRequirement(req);
  const parens = parts === null ? null : peelParens(parts.spec);
  if (parts === null || parens === null) return null;
  const clauses = parens.core.split(',').map(parseClause);
  if (clauses.some((c) => c === null)) return null;
  const parsed = clauses as Clause[];
  const lower = lowerBound(parsed, target);
  if (lower === null) return null;
  const body = parsed
    .map((c) => `${c.lead}${c.op}${c.gap}${c === lower ? target : c.version}${c.trail}`)
    .join(',');
  return `${parts.head}${parens.open}${body}${parens.close}${parts.tail}`;
}

const CONSTRAINT_OPERATOR = /^(?:\^|~|>=|==)/;
const CONSTRAINT_VERSION = /^\d[\w.+!-]*$/;

/**
 * A Poetry constraint with its version set to `target`: `^`, `~`, `>=`, `==` or none, spacing kept.
 * Null for `*`, `~=`, ranges, `||`, `!=`, wildcards, `<`, an empty constraint, a `~` with one
 * release number (its range would narrow), or a target that is no PEP 440 version.
 */
export function poetryConstraintWithTarget(c: string, target: string): string | null {
  if (!versionParses('pep440', target)) return null;
  const { lead, core, trail } = padded(c);
  const op = CONSTRAINT_OPERATOR.exec(core)?.[0] ?? '';
  const rest = padded(core.slice(op.length));
  const version = rest.core;
  if (!CONSTRAINT_VERSION.test(version) || !versionParses('pep440', version)) return null;
  if (op === '~' && releaseCount(version) < 2) return null;
  return `${lead}${op}${rest.lead}${target}${trail}`;
}

// ─── Files and edits ────────────────────────────────────────────────────────

/** A parsed file, or null for a text the parser refuses. */
function parsedOrNull(text: string): Doc | null {
  try {
    return readPyproject(text);
  } catch {
    return null;
  }
}

/** The manifests of the plan, read once, their planned changes, and the writing of the result. */
class Edits {
  private readonly bases = new Map<string, string>();
  private readonly texts = new Map<string, string>();
  private readonly docs = new Map<string, Doc>();
  private readonly mods = new Map<string, Mod[]>();

  constructor(private readonly ws: FixWorkspace) {}

  /** Reads and parses a manifest; the stop when it is a link or not TOML. */
  load(file: string): FixStop | null {
    if (this.docs.has(file)) return null;
    if (!isRegularFile(this.ws, file)) return notRegular(file);
    const text = readText(this.ws, file);
    try {
      this.docs.set(file, readPyproject(text));
    } catch (err) {
      return unsupported(`${file} cannot be read as TOML: ${clip(String(err))}`);
    }
    this.bases.set(file, text);
    this.texts.set(file, text);
    return null;
  }

  doc(file: string): Doc {
    return this.docs.get(file) ?? {};
  }

  text(file: string): string {
    return this.texts.get(file) ?? '';
  }

  set(file: string, text: string, mod: Mod): void {
    this.texts.set(file, text);
    this.mods.set(file, [...(this.mods.get(file) ?? []), mod]);
  }

  /** Each changed file, read back by the full parser, must equal its base with the planned changes. */
  problem(): FixStop | null {
    for (const [file, mods] of this.mods) {
      const expected = readPyproject(this.bases.get(file) ?? '');
      for (const mod of mods) setPath(expected, mod.path, mod.value);
      const actual = parsedOrNull(this.text(file));
      if (actual === null || !isDeepStrictEqual(actual, expected)) {
        return unsupported(
          `${file} cannot be edited in place without changing more than the planned entries.`,
        );
      }
    }
    return null;
  }

  write(): void {
    for (const file of this.mods.keys()) writeText(this.ws, file, this.text(file));
  }
}

// ─── Declarations ───────────────────────────────────────────────────────────

interface RequirementList {
  section: string;
  path: string[];
  override: boolean;
}

/** The PEP 508 lists of a manifest: PEP 621, its optional groups, PEP 735, and the uv overrides. */
function requirementLists(doc: Doc, manager: Manager): RequirementList[] {
  const plain = (section: string, path: string[]) => ({ section, path, override: false });
  const lists = [
    plain('project', ['project', 'dependencies']),
    ...keysOf(getPath(doc, ['project', 'optional-dependencies'])).map((g) =>
      plain('project.optional-dependencies', ['project', 'optional-dependencies', g]),
    ),
    ...keysOf(doc['dependency-groups']).map((g) =>
      plain('dependency-groups', ['dependency-groups', g]),
    ),
  ];
  if (manager === 'uv') {
    lists.push({ section: 'tool.uv', path: [...UV_PATH, OVERRIDES], override: true });
  }
  return lists;
}

function requirementsIn(file: string, doc: Doc, manager: Manager, pkg: string): Requirement[] {
  return requirementLists(doc, manager).flatMap(({ section, path, override }) => {
    const list = getPath(doc, path);
    if (!Array.isArray(list)) return [];
    return list.flatMap((entry: unknown, i): Requirement[] =>
      typeof entry === 'string' && requirementName(entry) === pkg
        ? [
            {
              kind: 'requirement',
              file,
              section,
              path: [...path, String(i)],
              text: entry,
              override,
            },
          ]
        : [],
    );
  });
}

/** Poetry's dependency tables: the main one and each group's. */
function poetryTables(doc: Doc): string[][] {
  const groups = keysOf(getPath(doc, ['tool', 'poetry', 'group']));
  return [
    POETRY_DEPENDENCIES,
    ...groups.map((g) => ['tool', 'poetry', 'group', g, 'dependencies']),
  ];
}

function poetryDependenciesIn(file: string, doc: Doc, pkg: string): PoetryDependency[] {
  return poetryTables(doc).flatMap((table) => {
    const entries = getPath(doc, table);
    if (!isRecord(entries)) return [];
    return Object.keys(entries)
      .filter((key) => normalizePythonName(key) === pkg)
      .map((key): PoetryDependency => ({ kind: 'poetry', file, table, key, value: entries[key] }));
  });
}

function declarationsIn(file: string, doc: Doc, manager: Manager, pkg: string): Declaration[] {
  const requirements = requirementsIn(file, doc, manager, pkg);
  return manager === 'poetry'
    ? [...requirements, ...poetryDependenciesIn(file, doc, pkg)]
    : requirements;
}

/** What Qualor does not edit in a manifest: a source for the package, a legacy dev table naming it. */
function manifestStop(file: string, doc: Doc, manager: Manager, pkg: string): FixStop | null {
  const named = (keys: string[]) => keys.some((k) => normalizePythonName(k) === pkg);
  if (manager === 'uv') {
    if (named(keysOf(getPath(doc, [...UV_PATH, 'sources'])))) {
      return unsupported(
        `${file} sets a source for ${pkg} in tool.uv.sources; Qualor does not change a package with its own source.`,
      );
    }
    const dev = getPath(doc, [...UV_PATH, 'dev-dependencies']);
    const names = Array.isArray(dev) ? dev.map((e) => requirementName(String(e))) : [];
    if (names.includes(pkg)) {
      return unsupported(
        `${file} lists ${pkg} in tool.uv.dev-dependencies, which Qualor does not edit; move it to a dependency group.`,
      );
    }
    return null;
  }
  if (named(keysOf(getPath(doc, ['tool', 'poetry', 'dev-dependencies'])))) {
    return unsupported(
      `${file} lists ${pkg} in tool.poetry.dev-dependencies, which Qualor does not edit; move it to a group.`,
    );
  }
  return null;
}

// ─── Editing ────────────────────────────────────────────────────────────────

/** The literal `old` in either quote style replaced by `next` in the section; null when absent. */
function replaceLiteral(text: string, section: string, old: string, next: string): string | null {
  for (const quote of ['"', "'"]) {
    const found = replaceInSection(
      text,
      section,
      `${quote}${old}${quote}`,
      `${quote}${next}${quote}`,
    );
    if (found !== null) return found;
  }
  return null;
}

function editRequirement(edits: Edits, d: Requirement, target: string): FixStop | null {
  const next = pep508WithTarget(d.text, target);
  if (next === null) {
    return unsupported(
      `${d.file} requires "${clip(d.text)}", which Qualor does not rewrite (a direct reference, or a range without a plain lower bound).`,
    );
  }
  const text = replaceLiteral(edits.text(d.file), d.section, d.text, next);
  if (text === null) {
    return unsupported(`${d.file} has "${clip(d.text)}" in a layout Qualor cannot edit in place.`);
  }
  edits.set(d.file, text, { path: d.path, value: next });
  return null;
}

/** A string literal's value replaced, the quote style kept; null when the text there differs. */
function replaceString(text: string, span: TomlSpan, old: string, next: string): string | null {
  const raw = text.slice(span.start, span.end);
  const quote = raw.charAt(0);
  if ((quote !== '"' && quote !== "'") || raw.length < 2 || !raw.endsWith(quote)) return null;
  if (raw.slice(1, -1) !== old) return null;
  return `${text.slice(0, span.start)}${quote}${next}${quote}${text.slice(span.end)}`;
}

/** `version = "…"` inside an inline table's text, replaced; null without exactly that. */
function replaceInlineVersion(text: string, span: TomlSpan, old: string, next: string) {
  const raw = text.slice(span.start, span.end);
  const match = /(\bversion\s*=\s*)(["'])([^"'\n]*)\2/.exec(raw);
  if (match === null || match[3] !== old) return null;
  const at = span.start + match.index;
  const literal = `${match[1] ?? ''}${match[2] ?? ''}${next}${match[2] ?? ''}`;
  return `${text.slice(0, at)}${literal}${text.slice(at + match[0].length)}`;
}

const POETRY_SOURCES = ['git', 'path', 'url', 'file'];

/** A Poetry entry's version text: the string itself, or the `version` of its table. */
function poetryVersion(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (!isRecord(value) || POETRY_SOURCES.some((k) => Object.hasOwn(value, k))) return null;
  const version = value['version'];
  return typeof version === 'string' ? version : null;
}

/** The text with the entry's version changed in the layout it is written in; null when it is not found. */
function poetryText(text: string, d: PoetryDependency, old: string, next: string): string | null {
  const inline = tomlValue(text, tomlSectionName(d.table), d.key);
  if (inline !== null) {
    return typeof d.value === 'string'
      ? replaceString(text, inline, old, next)
      : replaceInlineVersion(text, inline, old, next);
  }
  const own = tomlValue(text, tomlSectionName([...d.table, d.key]), 'version');
  return own === null ? null : replaceString(text, own, old, next);
}

function editPoetry(edits: Edits, d: PoetryDependency, target: string): FixStop | null {
  const old = poetryVersion(d.value);
  const next = old === null ? null : poetryConstraintWithTarget(old, target);
  const label = `${d.file}: ${d.key} in ${tomlSectionName(d.table)}`;
  if (old === null || next === null) {
    return unsupported(`${label} is not a plain version constraint Qualor rewrites.`);
  }
  const text = poetryText(edits.text(d.file), d, old, next);
  if (text === null) return unsupported(`${label} is in a layout Qualor cannot edit in place.`);
  const path = typeof d.value === 'string' ? [...d.table, d.key] : [...d.table, d.key, 'version'];
  edits.set(d.file, text, { path, value: next });
  return null;
}

function editDeclaration(edits: Edits, d: Declaration, target: string): FixStop | null {
  return d.kind === 'requirement'
    ? editRequirement(edits, d, target)
    : editPoetry(edits, d, target);
}

/** A uv override for a transitive package: `pkg>=<target>,<<next line>`, added to the array. */
function pinUv(edits: Edits, file: string, pkg: string, target: string): FixStop | null {
  const upper = nextLine(target);
  if (upper === null) return unsupported(`${target} has no release line Qualor can bound.`);
  const entry = `${pkg}>=${target},<${upper}`;
  const path = [...UV_PATH, OVERRIDES];
  const old = getPath(edits.doc(file), path);
  try {
    const text = setTomlArrayEntry(edits.text(file), 'tool.uv', OVERRIDES, entry);
    edits.set(file, text, { path, value: [...(Array.isArray(old) ? old : []), entry] });
  } catch (err) {
    return unsupported(`${file} cannot take an override in [tool.uv]: ${clip(String(err))}`);
  }
  return null;
}

/** The comment of a Poetry pin: what it is for and when to remove it (one line, ruling T16a). */
function pinComment(ids: readonly string[], dependents: readonly string[], target: string): string {
  const shownIds = ids.slice(0, FIX_MAX_DEPENDENTS).map(oneLine).join(', ');
  const more = ids.length > FIX_MAX_DEPENDENTS ? ', …' : '';
  const names = dependents.length === 0 ? 'its dependents' : dependents.map(oneLine).join(', ');
  return `# Qualor: pinned for ${shownIds}${more}; remove when ${names} require ${oneLine(target)} or later`;
}

/** A Poetry constraint for a transitive package in the main dependency table. */
function pinPoetry(
  edits: Edits,
  file: string,
  pkg: string,
  target: string,
  comment: string,
): FixStop | null {
  if (!/^[\w.+!-]+$/.test(target)) return unsupported(`${target} is not a plain version.`);
  const value = `^${target}`;
  try {
    const text = setTomlKey(
      edits.text(file),
      'tool.poetry.dependencies',
      pkg,
      `"${value}"`,
      comment,
    );
    edits.set(file, text, { path: [...POETRY_DEPENDENCIES, pkg], value });
  } catch (err) {
    return unsupported(
      `${file} cannot take a constraint in [tool.poetry.dependencies]: ${clip(String(err))}`,
    );
  }
  return null;
}

// ─── Lockfiles ──────────────────────────────────────────────────────────────

const inIgnoredFolder = (p: string) =>
  p
    .split('/')
    .slice(0, -1)
    .some((s) => s === 'node_modules' || s.startsWith('.'));

const isPythonLockfile = (p: string) => {
  const name = basename(p);
  return (name === UV_LOCK || name === POETRY_LOCK) && !inIgnoredFolder(p);
};

/** The lockfile's entries, by the shared readers (Task 4); a file they cannot read throws. */
function lockEntries(ws: FixWorkspace, lockfile: string): LockEntry[] {
  try {
    const text = readText(ws, lockfile);
    return basename(lockfile) === UV_LOCK ? readUvLock(text) : readPoetryLock(text);
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read ${lockfile}: ${why}`, { cause: err });
  }
}

/** The versions of the package (PEP 503 name), each once, in PEP 440 order. */
function versionsOf(entries: readonly LockEntry[], pkg: string): string[] {
  const versions = entries.filter((e) => e.name === pkg).map((e) => e.version);
  return [...new Set(versions)].toSorted(byVersion);
}

/** R6: who requires the package in the lockfile, at most {@link FIX_MAX_DEPENDENTS}. */
function dependentsOf(entries: readonly LockEntry[], pkg: string): string[] {
  const names = entries.filter((e) => e.name === pkg).flatMap((e) => e.dependents);
  return [...new Set(names)]
    .filter((n) => n !== pkg)
    .toSorted()
    .slice(0, FIX_MAX_DEPENDENTS);
}

function groupByLockfile(targets: readonly FixTarget[]): Map<string, FixTarget[]> {
  const out = new Map<string, FixTarget[]>();
  for (const t of targets) out.set(t.lockfile, [...(out.get(t.lockfile) ?? []), t]);
  return out;
}

// ─── Projects ───────────────────────────────────────────────────────────────

/** The project of a lockfile, or why it cannot be changed. */
function projectOf(
  ws: FixWorkspace,
  tracked: ReadonlySet<string>,
  lockfile: string,
): Project | FixStop {
  const dir = dirOf(lockfile);
  const pyproject = `${dir}${PYPROJECT}`;
  if (!tracked.has(pyproject)) {
    return unsupported(`${where(dir)} has a lockfile but no ${PYPROJECT}.`);
  }
  const other = `${dir}${basename(lockfile) === UV_LOCK ? POETRY_LOCK : UV_LOCK}`;
  if (tracked.has(other)) {
    return unsupported(
      `${where(dir)} has both ${UV_LOCK} and ${POETRY_LOCK}; Qualor changes one tool's lockfile.`,
    );
  }
  const link = [lockfile, pyproject].find((f) => !isRegularFile(ws, f));
  if (link !== undefined) return notRegular(link);
  const manager = basename(lockfile) === UV_LOCK ? 'uv' : 'poetry';
  return { dir, lockfile, manager, pyproject };
}

/** The project of each lockfile of the plan, in code-unit order of the lockfiles' paths. */
function projectsOf(ws: FixWorkspace, plan: FixPlan): Project[] | FixStop {
  const tracked = new Set(ws.files);
  const projects: Project[] = [];
  for (const lockfile of [...groupByLockfile(plan.targets).keys()].toSorted()) {
    const project = projectOf(ws, tracked, lockfile);
    if (isStop(project)) return project;
    projects.push(project);
  }
  return projects;
}

const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];

/** The `pyproject.toml` of the uv workspace's members (the root's `tool.uv.workspace`). */
function memberManifests(ws: FixWorkspace, root: Doc, project: Project): string[] {
  const workspace = getPath(root, [...UV_PATH, 'workspace']);
  const members = strings(isRecord(workspace) ? workspace['members'] : undefined);
  const excluded = strings(isRecord(workspace) ? workspace['exclude'] : undefined);
  if (members.length === 0) return [];
  const isIn = picomatch(members);
  const isOut = excluded.length === 0 ? () => false : picomatch(excluded);
  const owned = new Set(ws.files);
  return ws.files
    .filter(
      (p) => basename(p) === PYPROJECT && p !== project.pyproject && p.startsWith(project.dir),
    )
    .filter((p) => !inIgnoredFolder(p))
    .filter((p) => !owned.has(`${dirOf(p)}${UV_LOCK}`) && !owned.has(`${dirOf(p)}${POETRY_LOCK}`))
    .filter((p) => {
      const rel = dirOf(p).slice(project.dir.length, -1);
      return rel !== '' && isIn(rel) && !isOut(rel);
    })
    .toSorted();
}

/** The manifests of a project, loaded: its own, and for uv its workspace members'. */
function loadManifests(ws: FixWorkspace, edits: Edits, project: Project): string[] | FixStop {
  const stop = edits.load(project.pyproject);
  if (stop !== null) return stop;
  const members =
    project.manager === 'uv' ? memberManifests(ws, edits.doc(project.pyproject), project) : [];
  for (const member of members) {
    const memberStop = edits.load(member);
    if (memberStop !== null) return memberStop;
  }
  return [project.pyproject, ...members];
}

// ─── Planning ───────────────────────────────────────────────────────────────

const severalLines = (message: string): FixStop => ({
  kind: 'no_fix',
  reason: 'several_lines',
  message,
});

/**
 * B3: a transitive override or constraint covers every instance of the package, so a lockfile that
 * resolves it on several release lines cannot take one (and a direct fix with targets on several).
 */
function linesStop(
  fix: FixClaimItem,
  lockfile: string,
  versions: readonly string[],
  targets: readonly FixTarget[],
  relation: 'direct' | 'transitive',
): FixStop | null {
  const from = relation === 'transitive' ? versions : targets.map((t) => t.installed);
  const lines = [...new Set(from.map(lineOf))].toSorted(compareLines);
  if (lines.length < 2) return null;
  return severalLines(
    `${lockfile} resolves ${fix.packageName} on several release lines (${listed(lines.map(lineName))}); one pin cannot move each to its own fixed version.`,
  );
}

/** Edits the overrides that name the package, or adds the pin of a transitive package. */
function pinTransitive(
  edits: Edits,
  project: Project,
  fix: FixClaimItem,
  entries: readonly LockEntry[],
  target: string,
): FixStop | null {
  const pkg = normalizePythonName(fix.packageName);
  if (project.manager === 'uv') return pinUv(edits, project.pyproject, pkg, target);
  const comment = pinComment(
    fix.vulnerabilities.map((v) => v.id),
    dependentsOf(entries, pkg),
    target,
  );
  return pinPoetry(edits, project.pyproject, pkg, target, comment);
}

/** Plans one project's edits (not written yet), or the stop. */
function planProject(
  ws: FixWorkspace,
  edits: Edits,
  project: Project,
  fix: FixClaimItem,
  plan: FixPlan,
): ProjectPlan | FixStop {
  const pkg = normalizePythonName(fix.packageName);
  const targets = plan.targets.filter((t) => t.lockfile === project.lockfile);
  const target = greatestVersion(
    'pep440',
    targets.map((t) => t.target),
  );
  if (target === null) return unsupported(`no target of ${project.lockfile} is a PEP 440 version`);
  const files = loadManifests(ws, edits, project);
  if (isStop(files)) return files;
  for (const file of files) {
    const stop = manifestStop(file, edits.doc(file), project.manager, pkg);
    if (stop !== null) return stop;
  }
  const declared = files.flatMap((f) => declarationsIn(f, edits.doc(f), project.manager, pkg));
  const relation = declared.some((d) => d.kind === 'poetry' || !d.override)
    ? 'direct'
    : 'transitive';
  const entries = lockEntries(ws, project.lockfile);
  const lines = linesStop(fix, project.lockfile, versionsOf(entries, pkg), targets, relation);
  if (lines !== null) return lines;
  for (const d of declared) {
    const stop = editDeclaration(edits, d, target);
    if (stop !== null) return stop;
  }
  if (relation === 'transitive' && declared.length === 0) {
    const stop = pinTransitive(edits, project, fix, entries, target);
    if (stop !== null) return stop;
  }
  return { project, relation, mechanism: mechanismOf(project, relation) };
}

/** R6: how a transitive package is pinned. */
function mechanismOf(project: Project, relation: 'direct' | 'transitive'): string | null {
  if (relation === 'direct') return null;
  return project.manager === 'uv' ? OVERRIDES : 'constraint';
}

// ─── The tools ──────────────────────────────────────────────────────────────

const succeeded = (r: ToolResult) => r.exitCode === 0 && !r.timedOut;

/** What uv prints when no version of the requirements can be found together. */
const UV_NO_SOLUTION = /No solution found when resolving dependencies/;
/**
 * What uv prints when `--no-build` stopped it (ruling FW1): the solver's "building from source is
 * disabled", or a build's "Building source distributions (for `x`) is disabled". uv wraps its
 * lines, so a line break may sit between the words.
 */
const UV_BUILD_DISABLED =
  /building\s{1,16}(?:from\s{1,16}source|source\s{1,16}distributions?)(?:\s{1,16}for\s{1,16}\S{1,256})?\s{1,16}is\s{1,16}disabled/i;
/** The sentence a uv lock that needs a source build fails with (ruling FW1). */
const UV_NEEDS_BUILD =
  '`uv` needs to build a source distribution, which the fix job never does (--no-build)';
/** What Poetry prints when the constraints cannot be met. */
const POETRY_NO_SOLUTION = /version solving failed|SolverProblemError|doesn't match any versions/i;

const escapeRegExp = (s: string) => s.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);

/** Whether the text names the package (any spelling of its PEP 503 name, not a longer name). */
function namesPackage(text: string, pkg: string): boolean {
  const spelled = pkg.split('-').map(escapeRegExp).join('[-_.]+');
  return new RegExp(`(?<![A-Za-z\\d_.-])${spelled}(?![A-Za-z\\d_]|[-_.][A-Za-z\\d])`, 'i').test(
    text,
  );
}

/**
 * Ruling F36: the solver found no version for the target: `no_fix unresolvable`, when its output
 * names the package; any other failure (a Python version, a network error) is the tool's failure.
 * Ruling FW1: a uv lock that `--no-build` stopped is `package_manager`, and says why.
 */
function toolStop(tool: Manager, r: ToolResult, pkg: string): FixStop | null {
  if (succeeded(r)) return null;
  const output = `${r.stderr}\n${r.stdout}`;
  if (tool === 'uv' && !r.timedOut && UV_BUILD_DISABLED.test(output)) {
    return { kind: 'failure', ...toolFailure(tool, r, [], UV_NEEDS_BUILD) };
  }
  const failure = toolFailure(tool, r, []);
  const solver = tool === 'uv' ? UV_NO_SOLUTION : POETRY_NO_SOLUTION;
  if (!r.timedOut && solver.test(output) && namesPackage(output, pkg)) {
    return { kind: 'no_fix', reason: 'unresolvable', message: failure.message };
  }
  return { kind: 'failure', ...failure };
}

/**
 * The arguments of `poetry lock`: `--no-update` on Poetry 1.x (its `lock` would update every
 * package), none on 2.x; read from `poetry --version` before any file is written. Empty when the
 * plan has no Poetry project.
 */
async function poetryLockArgs(
  ws: FixWorkspace,
  projects: readonly Project[],
): Promise<string[] | FixStop> {
  const project = projects.find((p) => p.manager === 'poetry');
  if (project === undefined) return [];
  const r = await ws.run('poetry', ['--version'], {
    cwd: absolute(ws, project.dir),
    timeoutMs: timeLeft(ws),
  });
  if (!succeeded(r)) return { kind: 'failure', ...toolFailure('poetry', r, []) };
  const major = /\bversion\s+(\d+)\./i.exec(r.stdout)?.[1];
  if (major === undefined) {
    return {
      kind: 'failure',
      code: 'package_manager',
      message: `cannot read the Poetry version from "${clip(r.stdout.trim().slice(0, 60))}".`,
    };
  }
  return Number(major) >= 2
    ? ['lock', '--no-interaction']
    : ['lock', '--no-update', '--no-interaction'];
}

/** The project's own tool regenerates its lockfile. */
function regenerate(
  ws: FixWorkspace,
  project: Project,
  poetryArgs: readonly string[],
): Promise<ToolResult> {
  const uv = project.manager === 'uv';
  ws.log.debug(`python fix in ${where(project.dir)}: ${project.manager} lock`);
  return ws.run(project.manager, uv ? UV_LOCK_ARGS : poetryArgs, {
    cwd: absolute(ws, project.dir),
    ...(uv && { env: UV_ENV }),
    timeoutMs: timeLeft(ws),
  });
}

// ─── Verify ─────────────────────────────────────────────────────────────────

/**
 * B3: an instance still below its target (`installed <= v < target`) is `verify_failed`; a line
 * whose target stays on it that no longer has any instance (its instance was pushed across a
 * major) is `no_fix several_lines`.
 */
function verifyStop(ws: FixWorkspace, fix: FixClaimItem, plan: FixPlan): FixStop | null {
  const pkg = normalizePythonName(fix.packageName);
  const below: string[] = [];
  const moved: string[] = [];
  for (const [lockfile, targets] of groupByLockfile(plan.targets)) {
    const versions = versionsOf(lockEntries(ws, lockfile), pkg);
    for (const v of versions) {
      const t = targets.find((x) => byVersion(x.installed, v) <= 0 && byVersion(v, x.target) < 0);
      if (t !== undefined) {
        below.push(`${lockfile} still resolves ${fix.packageName} ${v}, below ${t.target}`);
      }
    }
    for (const t of targets) {
      const line = lineOf(t.installed);
      if (line !== lineOf(t.target) || versions.some((v) => lineOf(v) === line)) continue;
      moved.push(
        `${lockfile} moved ${fix.packageName} ${t.installed} off its release line ${lineName(line)}`,
      );
    }
  }
  if (below.length > 0) {
    return {
      kind: 'failure',
      code: 'verify_failed',
      message: `The lockfile did not reach the target: ${below.slice(0, 5).join('; ')}.`,
    };
  }
  if (moved.length === 0) return null;
  return severalLines(`${moved.slice(0, 5).join('; ')}.`);
}

// ─── The adapter ────────────────────────────────────────────────────────────

/** R6: each lockfile the tool changed, with its relation, pin and dependents. */
function lockfileLines(
  ws: FixWorkspace,
  pkg: string,
  plans: readonly ProjectPlan[],
  before: ReadonlyMap<string, string>,
): FixLockfile[] {
  return plans
    .filter(({ project }) => readText(ws, project.lockfile) !== before.get(project.lockfile))
    .map(({ project, relation, mechanism }) => ({
      path: project.lockfile,
      relation,
      mechanism,
      dependents: dependentsOf(lockEntries(ws, project.lockfile), pkg),
    }));
}

function planAll(
  ws: FixWorkspace,
  edits: Edits,
  projects: readonly Project[],
  fix: FixClaimItem,
  plan: FixPlan,
): ProjectPlan[] | FixStop {
  const plans: ProjectPlan[] = [];
  for (const project of projects) {
    const planned = planProject(ws, edits, project, fix, plan);
    if (isStop(planned)) return planned;
    plans.push(planned);
  }
  return plans;
}

/** Each project's lockfile regenerated by its tool; the first stop. */
async function regenerateAll(
  ws: FixWorkspace,
  projects: readonly Project[],
  poetryArgs: readonly string[],
  pkg: string,
): Promise<FixStop | null> {
  for (const project of projects) {
    const stop = toolStop(project.manager, await regenerate(ws, project, poetryArgs), pkg);
    if (stop !== null) return stop;
  }
  return null;
}

async function apply(
  ws: FixWorkspace,
  fix: FixClaimItem,
  plan: FixPlan,
): Promise<AppliedFix | FixStop> {
  const projects = projectsOf(ws, plan);
  if (isStop(projects)) return projects;
  const edits = new Edits(ws);
  const plans = planAll(ws, edits, projects, fix, plan);
  if (isStop(plans)) return plans;
  const poetryArgs = await poetryLockArgs(ws, projects);
  if (isStop(poetryArgs)) return poetryArgs;
  const refused = edits.problem();
  if (refused !== null) return refused;
  edits.write();
  const before = new Map(projects.map((p) => [p.lockfile, readText(ws, p.lockfile)]));
  const pkg = normalizePythonName(fix.packageName);
  const failed = await regenerateAll(ws, projects, poetryArgs, pkg);
  if (failed !== null) return failed;
  return verifyStop(ws, fix, plan) ?? { lockfiles: lockfileLines(ws, pkg, plans, before) };
}

/** A lockfile's versions of the package; none, with a warning, for a file the readers refuse. */
function installedIn(ws: FixWorkspace, lockfile: string, pkg: string): string[] {
  try {
    return versionsOf(lockEntries(ws, lockfile), pkg);
  } catch (err) {
    // A fixture or a broken lockfile elsewhere in the repository must not stop every Python fix.
    ws.log.warn(`skipping ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

/**
 * Every uv.lock and poetry.lock's versions of the package (by PEP 503 name; not in a folder of
 * dependencies or hidden folders, not a link), via the shared readers, in code-unit order.
 */
function installed(ws: FixWorkspace, packageName: string): Promise<InstalledAt[]> {
  const pkg = normalizePythonName(packageName);
  const found = ws.files
    .filter((p) => isPythonLockfile(p) && isRegularFile(ws, p))
    .toSorted()
    .map((lockfile) => ({ lockfile, versions: installedIn(ws, lockfile, pkg) }))
    .filter((at) => at.versions.length > 0);
  return Promise.resolve(found);
}

/** The Python family's adapter (Task 16): uv and Poetry. */
export const pythonAdapter: FixAdapter = {
  family: 'python',
  installed,
  apply,
  verify: (ws, fix, plan) => Promise.resolve(verifyStop(ws, fix, plan)),
};
