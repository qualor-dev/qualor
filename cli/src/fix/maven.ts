import path from 'node:path';
import {
  compareVersions,
  FIX_MAX_DEPENDENTS,
  greatestVersion,
  pomDependencyVersion,
  readPom,
  releaseLine,
  sameVersion,
  scrubToolOutput,
  type FixClaimItem,
  type FixLockfile,
  type FixTarget,
  type PomElement,
} from '@qualor/shared/fix';
import type {
  AppliedFix,
  FixAdapter,
  FixPlan,
  FixStop,
  FixWorkspace,
  InstalledAt,
} from './adapter';
import { addManagedDependency, replaceXmlText, xmlTextSpan } from './edit/xml';
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
 * The Maven family (spec §6.5, R6, R25, rulings F13, F16, F36, T4e). Maven has no lockfile: the
 * versions come from `mvn -B dependency:tree -Dincludes=<groupId>:<artifactId> -DoutputType=text`
 * at each top-level pom (the repository's root `pom.xml`, as a rule), read from its stdout (F16),
 * and the fix is a formatting-keeping edit of a `pom.xml` (`edit/xml.ts`). `mvn` comes from `PATH`
 * only, never the repository's `./mvnw` (R25).
 *
 * - **Where a version comes from:** each module of the tree is mapped to its tracked `pom.xml` (by
 *   `groupId:artifactId`) and its parent chain inside the repository (`<parent>` and
 *   `relativePath`). A direct dependency's version is the nearest `<dependencies>` entry with a
 *   `<version>`; else, and for a transitive one, the nearest `<dependencyManagement>` entry.
 * - **The edit:** that literal `<version>`, or the `${property}` it names when the same pom defines
 *   it (Task 4's check accepts a property change only there); a property only a parent defines is
 *   `manifest_unsupported` (F13). Nothing in the repository managing the version (transitive, or
 *   managed by an outside parent or an imported BOM): a `<dependencyManagement>` entry in the top
 *   pom of the module's chain, normally the root `pom.xml` (mechanism `dependencyManagement`).
 * - **Targets:** each names the pom the adapter edits (T4e). One edit serves every module that
 *   takes its version there, so modules on two release lines there are `no_fix several_lines`.
 * - **Verify:** the tree again; a version still below its target is `verify_failed`; Maven
 *   reporting a target missing is `no_fix unresolvable` (F36).
 *
 * `-q` is not passed although spec §6.5 and Ruling F16 name it: without `-DoutputFile`,
 * `dependency:tree` logs the tree at INFO level (`DependencyUtil.log`, `log::info`), which `-q`
 * hides, so its stdout would be empty. `-B` keeps the lines plain.
 */

interface Coordinates {
  groupId: string;
  artifactId: string;
}

/** A groupId or artifactId as `-Dincludes` takes it: no `:`, `,`, `*` or white space. */
const COORDINATE = /^[\w.-]+$/;

function coordinatesOf(packageName: string): Coordinates | null {
  const parts = packageName.split(':');
  const [groupId = '', artifactId = ''] = parts;
  if (parts.length !== 2 || !COORDINATE.test(groupId) || !COORDINATE.test(artifactId)) return null;
  return { groupId, artifactId };
}

const gaOf = (c: Coordinates) => `${c.groupId}:${c.artifactId}`;

/** Ruling T14c: one order for paths, by UTF-16 code units (never the locale's). */
function byCodeUnit(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

const verifyFailed = (message: string): FixStop => ({
  kind: 'failure',
  code: 'verify_failed',
  message,
});

/** At most this many modules or problems are named in a message. */
const SHOWN = 5;

const listed = (items: readonly string[]) =>
  items.length > SHOWN
    ? `${items.slice(0, SHOWN).join(', ')}, … (${items.length} in all)`
    : items.join(', ');

// ─── dependency:tree ────────────────────────────────────────────────────────

/** Ruling F16, T12j: stdout is parsed, so this much of it is kept; a longer one is cut. */
const TREE_OUTPUT_BYTES = 8 * 1024 * 1024;
/** The runner's tail drops up to 3 bytes of a character cut at its start. */
const CUT_SLACK_BYTES = 3;

const INFO = '[INFO] ';
/** `--- dependency:3.8.1:tree (default-cli) @ app ---` (Maven 3.9; 3.8 names maven-dependency-plugin). */
const GOAL_HEADER = /^--- \S+:tree \([^)]*\) @ \S+ ---$/;
/** A module's own line, the tree's root: `groupId:artifactId:packaging:version`. */
const MODULE_LINE = /^[^\s:]+:[^\s:]+:[^\s:]+:\S+$/;
/** `|  +- g:a:type:version:scope`: three characters per level above, then `+- ` or `\- `. */
const NODE_LINE = /^((?:\| {2}| {3})*)[+\\]- (\S+)/;

/** One node of a module's tree (depth 1: a direct dependency). */
interface TreeNode {
  ga: string;
  version: string;
  depth: number;
}

interface ModuleTree {
  /** The module's `groupId:artifactId`. */
  module: string;
  nodes: TreeNode[];
}

/**
 * The tree output read line by line: after a goal header, Maven may log downloads and warnings
 * before the module's line; the tree's lines follow it without a break.
 */
interface TreeReader {
  modules: ModuleTree[];
  goals: number;
  state: 'idle' | 'module' | 'tree';
  /** The first line that looks like a tree line but cannot be one. */
  problem: string | null;
}

/** `g:a:type:version:scope` or `g:a:type:classifier:version:scope`. */
function nodeOf(coords: string, depth: number): TreeNode | null {
  const parts = coords.split(':');
  if (parts.length < 5 || parts.length > 6 || parts.some((p) => p === '')) return null;
  return { ga: `${parts[0]}:${parts[1]}`, version: parts.at(-2) ?? '', depth };
}

function readOther(r: TreeReader, body: string | null): void {
  if (r.state === 'module' && body !== null && MODULE_LINE.test(body)) {
    const [groupId, artifactId] = body.split(':');
    r.modules.push({ module: `${groupId}:${artifactId}`, nodes: [] });
    r.state = 'tree';
  } else if (r.state === 'tree') {
    r.state = 'idle';
  }
}

function readNode(r: TreeReader, match: RegExpExecArray, body: string): void {
  const node = nodeOf(match[2] ?? '', (match[1] ?? '').length / 3 + 1);
  const module = r.modules.at(-1);
  if (r.state !== 'tree' || module === undefined || node === null) {
    r.problem ??= body;
    return;
  }
  module.nodes.push(node);
}

function feed(r: TreeReader, line: string): void {
  const body = line.startsWith(INFO) ? line.slice(INFO.length) : null;
  if (body !== null && GOAL_HEADER.test(body)) {
    r.goals += 1;
    r.state = 'module';
    return;
  }
  const node = body === null ? null : NODE_LINE.exec(body);
  if (node === null || body === null) readOther(r, body);
  else readNode(r, node, body);
}

const treeStop = (why: string): FixStop => ({
  kind: 'failure',
  code: 'package_manager',
  message: `\`mvn dependency:tree\` printed ${why}`,
});

/** Each module's tree in the output; a stop when it shows no tree or a line it cannot be. */
function readTrees(stdout: string): ModuleTree[] | FixStop {
  const r: TreeReader = { modules: [], goals: 0, state: 'idle', problem: null };
  for (const line of stdout.split('\n')) feed(r, line.endsWith('\r') ? line.slice(0, -1) : line);
  if (r.problem !== null) {
    // B9: the line is tool output, scrubbed like a failure's tail.
    return treeStop(
      `a tree line Qualor cannot read: ${scrubToolOutput(r.problem.slice(0, 200), [])}`,
    );
  }
  if (r.goals === 0) {
    return treeStop(
      'no dependency tree; Qualor reads its [INFO] lines (does .mvn/maven.config pass -q?).',
    );
  }
  return r.modules;
}

/** A node of the package and the node that brings it (`g:a`; null for a direct one). */
interface PackageNode {
  version: string;
  depth: number;
  parent: string | null;
}

function packageNodes(tree: ModuleTree, ga: string): PackageNode[] {
  const found: PackageNode[] = [];
  tree.nodes.forEach((node, i) => {
    if (node.ga !== ga) return;
    const above = tree.nodes.slice(0, i).findLast((n) => n.depth === node.depth - 1);
    const parent = node.depth === 1 ? null : (above?.ga ?? null);
    found.push({ version: node.version, depth: node.depth, parent });
  });
  return found;
}

const succeeded = (r: ToolResult) => r.exitCode === 0 && !r.timedOut;

/** The `[ERROR]` lines up to the first empty one, which starts Maven's help text. */
function leadingErrors(lines: readonly string[]): string[] {
  const errors = lines.filter((l) => l.startsWith('[ERROR]'));
  const help = errors.findIndex((l, i) => i > 0 && l.trim() === '[ERROR]');
  return help < 0 ? errors : errors.slice(0, help);
}

/** What a failure message quotes: Maven's errors (else its warnings) and stderr; else all stdout. */
function errorText(r: ToolResult): string {
  const lines = r.stdout.split(/\r?\n/);
  const errors = leadingErrors(lines);
  const own = errors.length > 0 ? errors : lines.filter((l) => l.startsWith('[WARNING]'));
  const text = [...own, r.stderr.trim()].filter((t) => t !== '').join('\n');
  return text === '' ? r.stdout : text;
}

/**
 * How Maven names an artifact it cannot find: a POM missing during the tree's collection (a
 * warning; the tree still shows the version), or a failed resolution.
 */
const MISSING: readonly { before: string; after: string }[] = [
  { before: 'The POM for ', after: ' is missing' },
  { before: 'Could not find artifact ', after: '' },
  { before: 'Failure to find ', after: '' },
];

/** The artifacts (`g:a:type[:classifier]:version`) the output reports missing. */
function missingArtifacts(output: string): string[] {
  const found: string[] = [];
  for (const { before, after } of MISSING) {
    for (let at = output.indexOf(before); at >= 0; at = output.indexOf(before, at + 1)) {
      const start = at + before.length;
      let end = start;
      while (end < output.length && output.charCodeAt(end) > 0x20) end += 1;
      if (output.startsWith(after, end)) found.push(output.slice(start, end));
    }
  }
  return found;
}

/** Ruling F36: Maven reports a target version of the package itself missing. */
function targetMissing(output: string, ga: string, targets: readonly string[]): boolean {
  return missingArtifacts(output).some((artifact) => {
    const parts = artifact.split(':');
    const version = parts.at(-1) ?? '';
    return (
      parts.length >= 4 &&
      `${parts[0]}:${parts[1]}` === ga &&
      targets.some((t) => sameVersion('maven', version, t))
    );
  });
}

/**
 * The trees of the reactor at `rootPom` (Ruling F16: stdout, 8 MiB kept; a cut one is never read):
 * a target Maven reports missing is `no_fix unresolvable` (F36), any other failure Maven's message
 * through `toolFailure` (B9).
 */
async function treesOf(
  ws: FixWorkspace,
  rootPom: string,
  c: Coordinates,
  targets: readonly string[],
): Promise<ModuleTree[] | FixStop> {
  const r = await ws.run(
    'mvn',
    ['-B', 'dependency:tree', `-Dincludes=${gaOf(c)}`, '-DoutputType=text'],
    {
      cwd: absolute(ws, dirOf(rootPom)),
      timeoutMs: timeLeft(ws),
      outputLimitBytes: TREE_OUTPUT_BYTES,
    },
  );
  const failure = toolFailure('mvn', { ...r, stderr: errorText(r) }, []);
  if (!r.timedOut && targetMissing(`${r.stdout}\n${r.stderr}`, gaOf(c), targets)) {
    return { kind: 'no_fix', reason: 'unresolvable', message: failure.message };
  }
  if (!succeeded(r)) return { kind: 'failure', ...failure };
  if (Buffer.byteLength(r.stdout, 'utf8') >= TREE_OUTPUT_BYTES - CUT_SLACK_BYTES) {
    return treeStop('more than 8 MiB; Qualor does not read a cut dependency tree.');
  }
  return readTrees(r.stdout);
}

// ─── Poms ───────────────────────────────────────────────────────────────────

interface Pom {
  path: string;
  project: PomElement;
  /** `groupId:artifactId`, the groupId inherited from `<parent>` when the pom has none. */
  ga: string;
  parent: { ga: string; relativePath: string | null } | null;
}

/** Folders that hold no module of a build: sources (fixtures, `src/it`), build output, hidden ones. */
const inIgnoredFolder = (p: string) =>
  p
    .split('/')
    .slice(0, -1)
    .some((s) => s === 'src' || s === 'target' || s === 'node_modules' || s.startsWith('.'));

const childText = (el: PomElement, name: string): string | null =>
  el.children.find((c) => c.name === name)?.text ?? null;

function pomOf(file: string, project: PomElement): Pom | null {
  if (project.name !== 'project') return null;
  const parent = project.children.find((c) => c.name === 'parent');
  const parentGroup = parent === undefined ? null : childText(parent, 'groupId');
  const groupId = childText(project, 'groupId') ?? parentGroup ?? '';
  return {
    path: file,
    project,
    ga: `${groupId}:${childText(project, 'artifactId') ?? ''}`,
    parent:
      parent === undefined
        ? null
        : {
            ga: `${parentGroup ?? ''}:${childText(parent, 'artifactId') ?? ''}`,
            relativePath: childText(parent, 'relativePath'),
          },
  };
}

/**
 * Every tracked `pom.xml` outside the folders that hold no module, read by Task 4's reader, by
 * path; a link is not read, and one the reader refuses is skipped with a warning.
 */
function readPoms(ws: FixWorkspace): Map<string, Pom> {
  const poms = new Map<string, Pom>();
  const files = ws.files.filter((p) => basename(p) === 'pom.xml' && !inIgnoredFolder(p));
  for (const file of files.toSorted(byCodeUnit)) {
    if (!isRegularFile(ws, file)) continue;
    try {
      const pom = pomOf(file, readPom(readText(ws, file)));
      if (pom !== null) poms.set(file, pom);
    } catch (err) {
      ws.log.warn(`skipping ${file}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return poms;
}

/** A folder's parents, up to the repository root (''). */
function foldersAbove(dir: string): string[] {
  const folders: string[] = [];
  let at = dir;
  while (at !== '') {
    at = dirOf(at.slice(0, -1));
    folders.push(at);
  }
  return folders;
}

/** The poms no other pom stands above: where `mvn` runs, in code-unit order. */
function topPoms(poms: ReadonlyMap<string, Pom>): string[] {
  return [...poms.keys()].filter(
    (file) => !foldersAbove(dirOf(file)).some((dir) => poms.has(`${dir}pom.xml`)),
  );
}

/** The tracked pom under the top pom's folder that builds a module of its tree. */
function modulePom(poms: ReadonlyMap<string, Pom>, root: string, module: string): Pom | FixStop {
  const under = dirOf(root);
  const found = [...poms.values()].filter((p) => p.path.startsWith(under) && p.ga === module);
  const [only] = found;
  if (found.length === 1 && only !== undefined) return only;
  const where = under === '' ? 'the repository' : under;
  return unsupported(
    found.length === 0
      ? `No tracked pom.xml in ${where} builds the module ${module} of the dependency tree.`
      : `Several tracked pom.xml files in ${where} build the module ${module}: ${listed(found.map((p) => p.path))}.`,
  );
}

/** The pom's parent inside the repository (`relativePath`, `../pom.xml` by default), when it is one. */
function parentPom(poms: ReadonlyMap<string, Pom>, pom: Pom): Pom | null {
  const parent = pom.parent;
  if (parent === null || parent.relativePath === '') return null;
  const relative = (parent.relativePath ?? '../pom.xml').replaceAll('\\', '/');
  const joined = path.posix.normalize(`${dirOf(pom.path)}${relative}`);
  // `normalize` leaves at most one trailing slash.
  const folder = joined.endsWith('/') ? joined : `${joined}/`;
  const file = joined.endsWith('.xml') ? joined : `${folder}pom.xml`;
  const found = poms.get(file);
  return found?.ga === parent.ga ? found : null;
}

/** The pom, its parent, and so on, as long as each is in the repository. */
function chainOf(poms: ReadonlyMap<string, Pom>, pom: Pom): Pom[] {
  const chain = [pom];
  let next = parentPom(poms, pom);
  while (next !== null && !chain.includes(next)) {
    chain.push(next);
    next = parentPom(poms, next);
  }
  return chain;
}

// ─── Where a version is set ─────────────────────────────────────────────────

type PomSection = 'dependencies' | 'dependencyManagement';

/** What the fix changes in a pom. */
type Edit =
  | { kind: 'version'; section: PomSection; from: string }
  | { kind: 'property'; name: string }
  | { kind: 'add' };

interface Site {
  pom: string;
  edit: Edit;
}

/** Where a module takes the package's version: an edit, or why there is none. */
type Place = Site | { pom: string; stop: FixStop };

const isSite = (place: Place): place is Site => 'edit' in place;

type Declared = NonNullable<ReturnType<typeof pomDependencyVersion>>;

/** A version Qualor rewrites: no range, no expression, no white space. */
const PLAIN_VERSION = /^[\w.+-]+$/;

/** Ruling F13: the declaring pom names a property it does not define. */
function parentProperty(pom: string, ga: string, property: string): FixStop {
  return unsupported(
    `${pom} takes the version of ${ga} from \${${property}}, which it does not define (a parent pom does); Qualor changes a property only in the pom that uses it for ${ga}.`,
  );
}

function siteOf(pom: string, ga: string, found: Declared): Place {
  if (found.property === null) {
    const from = found.version ?? '';
    if (PLAIN_VERSION.test(from))
      return { pom, edit: { kind: 'version', section: found.section, from } };
    return {
      pom,
      stop: unsupported(`${pom} gives ${ga} the version ${from}, which Qualor does not rewrite.`),
    };
  }
  if (found.version === null) return { pom, stop: parentProperty(pom, ga, found.property) };
  if (PLAIN_VERSION.test(found.version)) {
    return { pom, edit: { kind: 'property', name: found.property } };
  }
  return {
    pom,
    stop: unsupported(
      `${pom} sets \${${found.property}} for ${ga} to ${found.version}, which Qualor does not rewrite.`,
    ),
  };
}

const isVersioned = (found: Declared) => found.version !== null || found.property !== null;

/**
 * Where a module's version of the package is set, as Maven decides it: up its parent chain, the
 * nearest versioned `<dependencies>` entry (inherited ones too; an explicit version wins over any
 * management), else the nearest `<dependencyManagement>` entry; none in the repository (transitive,
 * or managed by an outside parent or BOM): a managed entry added to the chain's top.
 */
function placeOf(chain: readonly Pom[], ga: string, direct: boolean): Place {
  const declared = chain.flatMap((pom) => {
    const found = pomDependencyVersion(pom.project, ga);
    return found === null ? [] : [{ pom: pom.path, found }];
  });
  const own = declared.find((d) => d.found.section === 'dependencies' && isVersioned(d.found));
  if (own !== undefined) {
    if (direct) return siteOf(own.pom, ga, own.found);
    const why = `${own.pom} declares ${ga}, but the dependency tree has it only through another dependency.`;
    return { pom: own.pom, stop: unsupported(why) };
  }
  const managed = declared.find((d) => d.found.section === 'dependencyManagement');
  if (managed !== undefined) {
    if (isVersioned(managed.found)) return siteOf(managed.pom, ga, managed.found);
    const why = `${managed.pom} manages ${ga} without a version; Qualor adds no second entry for it.`;
    return { pom: managed.pom, stop: unsupported(why) };
  }
  return { pom: chain.at(-1)?.path ?? 'pom.xml', edit: { kind: 'add' } };
}

/** One module's version of the package, and where it is set. */
interface Use {
  module: string;
  version: string;
  parent: string | null;
  place: Place;
}

function usesOf(
  poms: ReadonlyMap<string, Pom>,
  root: string,
  trees: readonly ModuleTree[],
  ga: string,
): Use[] {
  return trees.flatMap((tree) => {
    const nodes = packageNodes(tree, ga);
    if (nodes.length === 0) return [];
    const pom = modulePom(poms, root, tree.module);
    return nodes.map((node) => ({
      module: tree.module,
      version: node.version,
      parent: node.parent,
      place: isStop(pom)
        ? { pom: root, stop: pom }
        : placeOf(chainOf(poms, pom), ga, node.depth === 1),
    }));
  });
}

// ─── Installed ──────────────────────────────────────────────────────────────

interface Analysis {
  packageName: string;
  uses: Use[];
}

/** What `installed` found, for `apply` on the same workspace. */
const ANALYSES = new WeakMap<FixWorkspace, Analysis>();

/** The tree of each top pom and where each module's version is set; a tree that fails throws. */
async function analyze(ws: FixWorkspace, packageName: string): Promise<Analysis> {
  const c = coordinatesOf(packageName);
  const uses: Use[] = [];
  if (c !== null) {
    const poms = readPoms(ws);
    for (const root of topPoms(poms)) {
      const trees = await treesOf(ws, root, c, []);
      if (isStop(trees)) throw new Error(trees.message);
      uses.push(...usesOf(poms, root, trees, gaOf(c)));
    }
  }
  const analysis = { packageName, uses };
  ANALYSES.set(ws, analysis);
  return analysis;
}

async function analysisOf(ws: FixWorkspace, packageName: string): Promise<Analysis> {
  const known = ANALYSES.get(ws);
  return known?.packageName === packageName ? known : analyze(ws, packageName);
}

/**
 * The package's versions in the trees, by the pom the fix edits for them (T4e: each target's
 * lockfile is that pom), in code-unit order.
 */
async function installed(ws: FixWorkspace, packageName: string): Promise<InstalledAt[]> {
  const { uses } = await analyze(ws, packageName);
  const byPom = new Map<string, string[]>();
  for (const use of uses) {
    const versions = byPom.get(use.place.pom) ?? [];
    if (!versions.some((v) => sameVersion('maven', v, use.version))) versions.push(use.version);
    byPom.set(use.place.pom, versions);
  }
  return [...byPom]
    .toSorted(([a], [b]) => byCodeUnit(a, b))
    .map(([lockfile, versions]) => ({ lockfile, versions }));
}

// ─── Apply ──────────────────────────────────────────────────────────────────

function editKey(edit: Edit): string {
  switch (edit.kind) {
    case 'version':
      return `version ${edit.section}`;
    case 'property':
      return `property ${edit.name}`;
    default:
      return 'add';
  }
}

const siteKey = (site: Site) => `${site.pom}\u0000${editKey(site.edit)}`;

/** One edit and the targets and modules it serves. */
interface SiteGroup {
  site: Site;
  targets: FixTarget[];
  uses: Use[];
}

/** The edits the targets need (a module whose version Qualor cannot change stops the fix). */
function siteGroups(
  uses: readonly Use[],
  targets: readonly FixTarget[],
): Map<string, SiteGroup> | FixStop {
  const groups = new Map<string, SiteGroup>();
  for (const target of targets) {
    const hit = uses.filter(
      (u) => u.place.pom === target.lockfile && sameVersion('maven', u.version, target.installed),
    );
    for (const use of hit) {
      if (!isSite(use.place)) return use.place.stop;
      const key = siteKey(use.place);
      const group = groups.get(key) ?? { site: use.place, targets: [], uses: [] };
      if (!group.targets.includes(target)) group.targets.push(target);
      group.uses.push(use);
      groups.set(key, group);
    }
  }
  return groups;
}

function editName(edit: Edit): string {
  if (edit.kind === 'property') return `property ${edit.name}`;
  return edit.kind === 'add' ? '<dependencyManagement> entry' : `<version> in <${edit.section}>`;
}

/**
 * The version one edit writes: the greatest of its targets and of the versions its modules already
 * have (so none of them goes down). Its modules on several release lines (B3): `no_fix
 * several_lines`, since one version would move some of them across a major.
 */
function versionFor(group: SiteGroup, uses: readonly Use[], ga: string): string | FixStop {
  const key = siteKey(group.site);
  const atSite = uses.filter((u) => isSite(u.place) && siteKey(u.place) === key);
  const lines = [...new Set(atSite.map((u) => releaseLine('maven', u.version) ?? u.version))];
  if (lines.length > 1) {
    const sorted = lines.toSorted((a, b) => compareVersions('maven', a, b) ?? byCodeUnit(a, b));
    const modules = listed([...new Set(atSite.map((u) => u.module))]);
    return {
      kind: 'no_fix',
      reason: 'several_lines',
      message: `${ga} is on the release lines ${sorted.join(', ')} in the modules ${modules}, and the one ${editName(group.site.edit)} of ${group.site.pom} sets a single version for all of them.`,
    };
  }
  const candidates = [...group.targets.map((t) => t.target), ...atSite.map((u) => u.version)];
  return greatestVersion('maven', candidates) ?? group.targets[0]?.target ?? '';
}

const SECTION_PATH: Readonly<Record<PomSection, readonly string[]>> = {
  dependencies: ['project', 'dependencies', 'dependency', 'version'],
  dependencyManagement: [
    'project',
    'dependencyManagement',
    'dependencies',
    'dependency',
    'version',
  ],
};

/** Every `<version>` of the package in the section that reads `from` (Review Focus 3: by groupId too). */
function setVersions(
  text: string,
  pom: string,
  c: Coordinates,
  edit: { section: PomSection; from: string },
  version: string,
): string | FixStop {
  if (edit.from === version) return text;
  const isOld = (dependency: PomElement) =>
    childText(dependency, 'groupId') === c.groupId &&
    childText(dependency, 'artifactId') === c.artifactId &&
    childText(dependency, 'version') === edit.from;
  let span = xmlTextSpan(text, SECTION_PATH[edit.section], isOld);
  if (span === null) {
    return unsupported(
      `Qualor cannot rewrite the <version> of ${gaOf(c)} in ${pom} alone (a comment or an element inside it?).`,
    );
  }
  let next = text;
  while (span !== null) {
    next = replaceXmlText(next, span, version);
    span = xmlTextSpan(next, SECTION_PATH[edit.section], isOld);
  }
  return next;
}

function setProperty(text: string, pom: string, name: string, version: string): string | FixStop {
  const span = xmlTextSpan(text, ['project', 'properties', name]);
  if (span === null) {
    return unsupported(`Qualor cannot rewrite the property ${name} in ${pom} alone.`);
  }
  return replaceXmlText(text, span, version);
}

function addEntry(text: string, pom: string, c: Coordinates, version: string): string | FixStop {
  try {
    return addManagedDependency(text, gaOf(c), version);
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    return unsupported(`Qualor cannot add a <dependencyManagement> entry to ${pom}: ${why}`);
  }
}

interface PlannedEdit {
  site: Site;
  version: string;
}

function editPom(text: string, planned: PlannedEdit, c: Coordinates): string | FixStop {
  const { site, version } = planned;
  switch (site.edit.kind) {
    case 'version':
      return setVersions(text, site.pom, c, site.edit, version);
    case 'property':
      return setProperty(text, site.pom, site.edit.name, version);
    default:
      return addEntry(text, site.pom, c, version);
  }
}

function plannedEdits(
  groups: readonly SiteGroup[],
  uses: readonly Use[],
  ga: string,
): PlannedEdit[] | FixStop {
  const edits: PlannedEdit[] = [];
  for (const group of groups) {
    const version = versionFor(group, uses, ga);
    if (isStop(version)) return version;
    edits.push({ site: group.site, version });
  }
  return edits;
}

/** An added entry goes in after the pom's other edits. */
const addedLast = (a: PlannedEdit, b: PlannedEdit) =>
  Number(a.site.edit.kind === 'add') - Number(b.site.edit.kind === 'add');

/** Each pom's edits, read and written through the link guard, in code-unit order of the poms. */
function writeEdits(
  ws: FixWorkspace,
  edits: readonly PlannedEdit[],
  c: Coordinates,
): FixStop | null {
  const poms = [...new Set(edits.map((e) => e.site.pom))].toSorted(byCodeUnit);
  for (const pom of poms) {
    if (!isRegularFile(ws, pom)) return notRegular(pom);
    let text = readText(ws, pom);
    for (const edit of edits.filter((e) => e.site.pom === pom).toSorted(addedLast)) {
      const next = editPom(text, edit, c);
      if (isStop(next)) return next;
      text = next;
    }
    writeText(ws, pom, text);
  }
  return null;
}

/**
 * R6: each edited pom; `transitive` through `dependencyManagement` when the fix added a managed
 * entry there (its dependents: the dependencies that bring the package), else `direct`.
 */
function lockfileLines(groups: readonly SiteGroup[]): FixLockfile[] {
  const poms = [...new Set(groups.map((g) => g.site.pom))].toSorted(byCodeUnit);
  return poms.map((pom) => {
    const pins = groups.filter((g) => g.site.pom === pom && g.site.edit.kind === 'add');
    if (pins.length === 0)
      return { path: pom, relation: 'direct', mechanism: null, dependents: [] };
    const parents = pins.flatMap((g) => g.uses.map((u) => u.parent));
    const dependents = [...new Set(parents.filter((p): p is string => p !== null))]
      .toSorted(byCodeUnit)
      .slice(0, FIX_MAX_DEPENDENTS);
    return { path: pom, relation: 'transitive', mechanism: 'dependencyManagement', dependents };
  });
}

function editLine(edit: PlannedEdit): string {
  return `${editName(edit.site.edit)} of ${edit.site.pom} to ${edit.version}`;
}

async function apply(
  ws: FixWorkspace,
  fix: FixClaimItem,
  plan: FixPlan,
): Promise<AppliedFix | FixStop> {
  const c = coordinatesOf(fix.packageName);
  if (c === null) return unsupported(`${fix.packageName} is not a Maven groupId:artifactId.`);
  const { uses } = await analysisOf(ws, fix.packageName);
  const groups = siteGroups(uses, plan.targets);
  if (isStop(groups)) return groups;
  const edits = plannedEdits([...groups.values()], uses, fix.packageName);
  if (isStop(edits)) return edits;
  ws.log.debug(`maven fix: setting the ${edits.map(editLine).join('; ')}`);
  const stop = writeEdits(ws, edits, c);
  return stop ?? { lockfiles: lockfileLines([...groups.values()]) };
}

// ─── Verify ─────────────────────────────────────────────────────────────────

/** B3: each module's version of the package that some target's `installed ≤ v < target` holds for. */
function belowTargets(
  trees: readonly ModuleTree[],
  ga: string,
  targets: readonly FixTarget[],
): string[] {
  return trees.flatMap((tree) =>
    packageNodes(tree, ga).flatMap(({ version }) => {
      const t = targets.find(
        (x) =>
          (compareVersions('maven', x.installed, version) ?? 1) <= 0 &&
          (compareVersions('maven', version, x.target) ?? 0) < 0,
      );
      return t === undefined ? [] : [`${tree.module} resolves ${version}, below ${t.target}`];
    }),
  );
}

/** The tree again at each top pom: null when every module reached its target. */
async function verifyStop(
  ws: FixWorkspace,
  fix: FixClaimItem,
  plan: FixPlan,
): Promise<FixStop | null> {
  const c = coordinatesOf(fix.packageName);
  if (c === null) return verifyFailed(`${fix.packageName} is not a Maven groupId:artifactId.`);
  const targets = plan.targets.map((t) => t.target);
  const problems: string[] = [];
  for (const root of topPoms(readPoms(ws))) {
    const trees = await treesOf(ws, root, c, targets);
    if (isStop(trees)) return trees;
    problems.push(...belowTargets(trees, gaOf(c), plan.targets));
  }
  if (problems.length === 0) return null;
  return verifyFailed(
    `\`mvn dependency:tree\` still resolves ${fix.packageName} below its target: ${listed(problems)}.`,
  );
}

/** The Maven family's adapter (Task 15): pom edits, checked through `mvn dependency:tree`. */
export const mavenAdapter: FixAdapter = {
  family: 'maven',
  installed,
  apply,
  verify: verifyStop,
};
