import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import picomatch from 'picomatch';
import { parse as parseYaml } from 'yaml';
import {
  compareVersions,
  FIX_FILES,
  FIX_MAX_DEPENDENTS,
  greatestVersion,
  isPlainSpec,
  pinsPackage,
  readNpmLock,
  readPnpmLock,
  readYarnLock,
  releaseLine,
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
import { addJsonProperty, setJsonString } from './edit/json';
import { isRewritableRange, rangeAllows, rangeWithTarget } from './edit/ranges';
import { setYamlOverride } from './edit/yaml';
import { toolFailure, type ToolResult } from './runner';

/**
 * The JS family (spec §6.5, B3, B7, R22, R23): npm, pnpm, Yarn classic and Yarn Berry. One edit
 * path for all of them (R22): a formatting-keeping text edit of `package.json` (or of
 * `pnpm-workspace.yaml`, ruling F15), then the manager's own lockfile regeneration with scripts
 * off, in the folder of each lockfile that resolves the package to a vulnerable version.
 *
 * - **Direct** (a dependency section of the folder's `package.json` or of one of its workspaces
 *   declares the package with a range that allows a vulnerable version): that range is raised to
 *   its target, its operator kept (`rangeWithTarget`).
 * - **Transitive**: a pin in the root manifest, `overrides` (npm), `pnpm.overrides` or the
 *   `overrides` of `pnpm-workspace.yaml` when that file has them (pnpm), `resolutions` (Yarn). A
 *   package on one release line gets one unscoped key; on several lines each vulnerable line gets
 *   its own key (R23): npm and pnpm `pkg@>=M.0.0 <M+1.0.0`, Yarn Berry the lockfile's own
 *   descriptors of that line (`pkg@npm:^1.2.0`: Berry matches a resolution's range by its text, so
 *   R23's `pkg@npm:^M.0.0` would only catch a dependency declared as exactly `^M.0.0`), and Yarn
 *   classic, which cannot scope, ends `no_fix several_lines`.
 *
 * Every lockfile of the family beside a changed manifest is regenerated (B7), each manager with the
 * other files of the folder put back after it (npm rewrites a `yarn.lock` it finds; Berry rewrites
 * `package.json`), so only the planned edit and the lockfiles change.
 */

type Manager = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry';

interface Lockfile {
  path: string;
  manager: Manager;
}

/** A folder with a `package.json` and the lockfiles beside it. */
interface Project {
  /** '' at the repository root, else the folder with a trailing `/`. */
  dir: string;
  manifest: string;
  /** The `package.json` of each workspace (npm and Yarn `workspaces`, pnpm `packages`). */
  members: string[];
  /** In the order they are regenerated: npm, pnpm, Yarn. */
  lockfiles: Lockfile[];
  /** `pnpm-workspace.yaml` beside the manifest, when tracked. */
  workspaceYaml: string | null;
}

/** What `apply` decided for a project: its relation, and each lockfile's pin (R6). */
interface ProjectPlan {
  project: Project;
  relation: 'direct' | 'transitive';
  mechanisms: Map<string, string | null>;
}

type Json = Record<string, unknown>;

const BOM = '\uFEFF';
const DIRECT_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

const isRecord = (v: unknown): v is Json =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isStop = (v: unknown): v is FixStop => isRecord(v) && 'kind' in v;
const unsupported = (message: string): FixStop => ({
  kind: 'failure',
  code: 'manifest_unsupported',
  message,
});
const severalLines = (message: string): FixStop => ({
  kind: 'no_fix',
  reason: 'several_lines',
  message,
});

// ─── Files ──────────────────────────────────────────────────────────────────

const basename = (p: string) => p.slice(p.lastIndexOf('/') + 1);
/** A repository path's folder with its slash ('' at the root). */
const dirOf = (p: string) => p.slice(0, p.lastIndexOf('/') + 1);
const inNodeModules = (p: string) => p.split('/').includes('node_modules');
const isJsLockfile = (p: string) =>
  FIX_FILES.js.lockfiles.includes(basename(p)) && !inNodeModules(p);

const absolute = (ws: FixWorkspace, rel: string) => path.join(ws.root, ...rel.split('/'));
const readText = (ws: FixWorkspace, rel: string) => readFileSync(absolute(ws, rel), 'utf8');
const writeText = (ws: FixWorkspace, rel: string, text: string) =>
  writeFileSync(absolute(ws, rel), text, 'utf8');
const stripBom = (text: string) => (text.startsWith(BOM) ? text.slice(1) : text);

/** Whether a repository path is a regular file of the scratch copy: not a link, not missing. */
function isRegularFile(ws: FixWorkspace, rel: string): boolean {
  try {
    return lstatSync(absolute(ws, rel)).isFile();
  } catch {
    return false;
  }
}

/** A link is followed by every read and write: the edit could land outside the scratch copy. */
const notRegular = (file: string): FixStop =>
  unsupported(`${file} is not a regular file (a link?); Qualor edits only regular files.`);

function parseManifest(text: string): Json | null {
  try {
    const value: unknown = JSON.parse(stripBom(text));
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

/** As Yarn decides it: a `# yarn lockfile v1` line among the leading comment lines. */
function isYarnClassic(text: string): boolean {
  for (const line of stripBom(text).split(/\r\n|\r|\n/, 64)) {
    if (!line.startsWith('#')) return false;
    if (/^#\s+yarn\s+lockfile\s+v1$/i.test(line)) return true;
  }
  return false;
}

function managerOf(lockfile: string, text: string): Manager {
  const name = basename(lockfile);
  if (name === 'pnpm-lock.yaml') return 'pnpm';
  if (name !== 'yarn.lock') return 'npm';
  return isYarnClassic(text) ? 'yarn-classic' : 'yarn-berry';
}

function readerOf(lockfile: string): (text: string) => LockEntry[] {
  const name = basename(lockfile);
  if (name === 'pnpm-lock.yaml') return readPnpmLock;
  return name === 'yarn.lock' ? readYarnLock : readNpmLock;
}

/** The lockfile's entries, by the shared readers (Task 3); a file they cannot read throws. */
function lockEntries(ws: FixWorkspace, lockfile: string): LockEntry[] {
  try {
    return readerOf(lockfile)(readText(ws, lockfile));
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new Error(`cannot read ${lockfile}: ${why}`, { cause: err });
  }
}

const bySemver = (a: string, b: string) => compareVersions('semver', a, b) ?? a.localeCompare(b);
const lineOf = (v: string) => releaseLine('semver', v) ?? v;
const lineName = (line: string) => `${line}.x`;

function listed(items: readonly string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items.at(-1) ?? ''}`;
}

/** The versions of the package (not of an alias in its slot), each once, in SemVer order. */
function versionsOf(entries: readonly LockEntry[], packageName: string): string[] {
  const versions = entries.filter((e) => e.name === packageName).map((e) => e.version);
  return [...new Set(versions)].toSorted(bySemver);
}

// ─── Projects ───────────────────────────────────────────────────────────────

const MANAGER_ORDER: Readonly<Record<Manager, number>> = {
  npm: 0,
  pnpm: 1,
  'yarn-classic': 2,
  'yarn-berry': 2,
};

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** A glob without a leading `./` and trailing slashes. */
function normalizeGlob(p: string): string {
  let end = p.length;
  while (end > 0 && p.charAt(end - 1) === '/') end -= 1;
  return p.slice(p.startsWith('./') ? 2 : 0, end);
}

/** The workspace globs: `workspaces` (an array, or `{ packages }`) and pnpm's `packages`. */
function workspacePatterns(manifest: Json, workspaceYaml: unknown): string[] {
  const field = manifest['workspaces'];
  const fromJson = isRecord(field) ? strings(field['packages']) : strings(field);
  const fromYaml = isRecord(workspaceYaml) ? strings(workspaceYaml['packages']) : [];
  return [...fromJson, ...fromYaml].map(normalizeGlob);
}

/** The tracked `package.json` files of the workspaces under `dir`. */
function membersOf(tracked: readonly string[], dir: string, patterns: readonly string[]): string[] {
  const include = patterns.filter((p) => !p.startsWith('!'));
  const exclude = patterns.filter((p) => p.startsWith('!')).map((p) => p.slice(1));
  if (include.length === 0) return [];
  const isIn = picomatch(include);
  const isOut = exclude.length === 0 ? () => false : picomatch(exclude);
  return tracked
    .filter((p) => basename(p) === 'package.json' && p.startsWith(dir) && !inNodeModules(p))
    .filter((p) => {
      const rel = p.slice(dir.length, -'/package.json'.length);
      return rel !== '' && p !== `${dir}package.json` && isIn(rel) && !isOut(rel);
    })
    .toSorted();
}

function readWorkspaceYaml(ws: FixWorkspace, file: string | null): unknown {
  if (file === null) return null;
  try {
    return parseYaml(readText(ws, file)) as unknown;
  } catch {
    return null;
  }
}

/** The project of one folder: its manifest, workspaces and lockfiles. */
function projectAt(ws: FixWorkspace, tracked: ReadonlySet<string>, dir: string): Project | FixStop {
  const manifest = `${dir}package.json`;
  if (!tracked.has(manifest)) {
    return unsupported(
      `${dir === '' ? 'The repository root' : dir} has a lockfile but no package.json.`,
    );
  }
  if (!isRegularFile(ws, manifest)) return notRegular(manifest);
  const json = parseManifest(readText(ws, manifest));
  if (json === null) return unsupported(`${manifest} is not a JSON object.`);
  const yamlFile = tracked.has(`${dir}pnpm-workspace.yaml`) ? `${dir}pnpm-workspace.yaml` : null;
  const paths = ws.files.filter((p) => isJsLockfile(p) && dirOf(p) === dir);
  const link = [...paths, ...(yamlFile === null ? [] : [yamlFile])].find(
    (f) => !isRegularFile(ws, f),
  );
  if (link !== undefined) return notRegular(link);
  const patterns = workspacePatterns(json, readWorkspaceYaml(ws, yamlFile));
  const members = membersOf(ws.files, dir, patterns);
  const linkedMember = members.find((f) => !isRegularFile(ws, f));
  if (linkedMember !== undefined) return notRegular(linkedMember);
  const lockfiles = paths
    .map((p) => ({ path: p, manager: managerOf(p, readText(ws, p)) }))
    .toSorted(
      (a, b) => MANAGER_ORDER[a.manager] - MANAGER_ORDER[b.manager] || a.path.localeCompare(b.path),
    );
  return {
    dir,
    manifest,
    members,
    lockfiles,
    workspaceYaml: yamlFile,
  };
}

/** The projects of the folders whose lockfiles hold a vulnerable version (the plan's targets). */
function projectsOf(ws: FixWorkspace, plan: FixPlan): Project[] | FixStop {
  const tracked = new Set(ws.files);
  const dirs = [...new Set(plan.targets.map((t) => dirOf(t.lockfile)))].toSorted();
  const projects: Project[] = [];
  for (const dir of dirs) {
    const project = projectAt(ws, tracked, dir);
    if (isStop(project)) return project;
    projects.push(project);
  }
  return projects;
}

/** R22: Yarn's zero-install cache is tracked; regenerating `yarn.lock` would leave it stale. */
function zeroInstallStop(ws: FixWorkspace, projects: readonly Project[]): FixStop | null {
  for (const project of projects) {
    if (!project.lockfiles.some((l) => l.manager !== 'npm' && l.manager !== 'pnpm')) continue;
    const cache = `${project.dir}.yarn/cache/`;
    if (ws.files.some((p) => p.startsWith(cache))) {
      return unsupported(
        `${cache.slice(0, -1)} is tracked: a Yarn zero-install repository, whose cache Qualor does not update.`,
      );
    }
  }
  return null;
}

/** Ruling T13f: what a Berry lockfile entry may resolve to; a `patch:` must patch one of them. */
const BERRY_SOURCES: readonly string[] = ['npm:', 'workspace:'];

/** The reference after `name@` of a descriptor or locator (a scope keeps its `@`); null without one. */
function referenceOf(descriptor: string): string | null {
  const at = descriptor.indexOf('@', 1);
  return at < 1 ? null : descriptor.slice(at + 1);
}

const protocolOf = (reference: string) => reference.slice(0, reference.indexOf(':') + 1);

/** The locator a `patch:` reference patches (`other@npm:1.0.0`), decoded; null when unreadable. */
function patchedLocator(reference: string): string | null {
  const body = reference.slice('patch:'.length).split('::', 1)[0] ?? '';
  const hash = body.indexOf('#');
  if (hash < 0) return null;
  try {
    return decodeURIComponent(body.slice(0, hash));
  } catch {
    return null;
  }
}

/** Whether a Berry resolution is the npm registry, a workspace, or a patch of one of those. */
function allowedBerryResolution(resolution: string): boolean {
  const reference = referenceOf(resolution);
  if (reference === null) return false;
  const protocol = protocolOf(reference);
  if (BERRY_SOURCES.includes(protocol)) return true;
  const patched = protocol === 'patch:' ? patchedLocator(reference) : null;
  const inner = patched === null ? null : referenceOf(patched);
  return inner !== null && BERRY_SOURCES.includes(protocolOf(inner));
}

/** The first entry of a Berry lockfile that resolves anywhere else: its key and resolution. */
function foreignBerryEntry(text: string): { key: string; resolution: string } | null {
  const lock: unknown = parseYaml(text, { schema: 'failsafe' });
  if (!isRecord(lock)) return { key: '(the whole file)', resolution: '' };
  for (const [key, entry] of Object.entries(lock)) {
    if (key === '__metadata') continue;
    const resolution = isRecord(entry) ? entry['resolution'] : undefined;
    if (typeof resolution !== 'string') return { key, resolution: '' };
    if (!allowedBerryResolution(resolution)) return { key, resolution };
  }
  return null;
}

/**
 * Rulings T13c and T13f: Yarn Berry prepares a dependency from git, ssh, `exec:` (a generator
 * script), a tarball URL, `file:`, `link:` or `portal:` by fetching and building it, and
 * `enableScripts: false` may not cover that step. So under Berry every lockfile entry must resolve
 * to the npm registry, a workspace, or a patch of one of those; any other source is left to a
 * person, before any tool runs. npm and pnpm skip the prepare step under `--ignore-scripts`.
 */
function berrySourceStop(ws: FixWorkspace, projects: readonly Project[]): FixStop | null {
  for (const project of projects) {
    for (const lockfile of project.lockfiles.filter((l) => l.manager === 'yarn-berry')) {
      const foreign = foreignBerryEntry(readText(ws, lockfile.path));
      if (foreign !== null) {
        return unsupported(
          `${lockfile.path}: the entry ${specText(foreign.key)} resolves to ${specText(foreign.resolution)}; under Yarn Berry, Qualor regenerates only a lockfile whose entries come from the npm registry, a workspace or a patch of one of those, since Yarn may run scripts to prepare any other source.`,
        );
      }
    }
  }
  return null;
}

/** Ruling T13g: the manifest sections whose specs Berry resolves (and `resolutions`, its pins). */
const BERRY_SPEC_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
  'resolutions',
] as const;

/** An npm dist-tag (`latest`, `next`, `beta-2`): a word, no `:`, `/` or white space. */
const DIST_TAG = /^[A-Za-z][\w.-]*$/;
/** A package name, scoped or not, as an `npm:` alias names it. */
const ALIASED_NAME = /^(?:@[\w.~-]+\/)?[\w.~-]+$/;

const isRangeOrTag = (spec: string) => spec === '' || isPlainSpec(spec) || DIST_TAG.test(spec);

/** `npm:<range or tag>` or an alias `npm:<name>[@<range or tag>]`, after the `npm:`. */
function isNpmSpec(rest: string): boolean {
  if (isRangeOrTag(rest)) return true;
  const at = rest.indexOf('@', 1);
  const name = at < 1 ? rest : rest.slice(0, at);
  return ALIASED_NAME.test(name) && (at < 1 || isRangeOrTag(rest.slice(at + 1)));
}

/** A range or tag, `npm:` (aliases included) or `workspace:`. */
function isRegistryOrWorkspaceSpec(spec: string): boolean {
  if (spec.startsWith('npm:')) return isNpmSpec(spec.slice('npm:'.length));
  return spec.startsWith('workspace:') || isRangeOrTag(spec);
}

/**
 * Ruling T13g: a manifest spec Berry resolves without fetching or building anything itself: a
 * range or dist-tag, `npm:` (aliases included), `workspace:`, or a `patch:` of one of those.
 */
function allowedBerrySpec(spec: string): boolean {
  if (!spec.startsWith('patch:')) return isRegistryOrWorkspaceSpec(spec);
  const patched = patchedLocator(spec);
  const range = patched === null ? null : referenceOf(patched);
  return range !== null && isRegistryOrWorkspaceSpec(range);
}

/** The first spec of a manifest that Berry would fetch from elsewhere: its section, name and spec. */
function foreignSpec(manifest: Json): { section: string; name: string; spec: unknown } | null {
  for (const section of BERRY_SPEC_SECTIONS) {
    const specs = manifest[section];
    if (!isRecord(specs)) continue;
    for (const [name, spec] of Object.entries(specs)) {
      if (typeof spec !== 'string' || !allowedBerrySpec(spec)) return { section, name, spec };
    }
  }
  return null;
}

/** One Berry project's manifests: the first spec the allowlist refuses, as a stop. */
function berryManifestsStop(ws: FixWorkspace, project: Project): FixStop | null {
  for (const file of [project.manifest, ...project.members]) {
    const manifest = parseManifest(readText(ws, file));
    if (manifest === null) return unsupported(`${file} is not a JSON object.`);
    const foreign = foreignSpec(manifest);
    if (foreign !== null) {
      return unsupported(
        `${file} declares ${foreign.name} as ${specText(foreign.spec)} in ${foreign.section}; under Yarn Berry, Qualor fixes only a project whose specs are ranges, tags, npm:, workspace: or a patch of those, since Yarn may run scripts to prepare any other source.`,
      );
    }
  }
  return null;
}

/**
 * Ruling T13g: Berry also resolves the manifests' specs that are not in the lockfile yet, so under
 * Berry every spec of the root and workspace manifests passes {@link allowedBerrySpec}, before any
 * tool runs.
 */
function berrySpecStop(ws: FixWorkspace, projects: readonly Project[]): FixStop | null {
  for (const project of projects) {
    if (!project.lockfiles.some((l) => l.manager === 'yarn-berry')) continue;
    const stop = berryManifestsStop(ws, project);
    if (stop !== null) return stop;
  }
  return null;
}

// ─── Edits ──────────────────────────────────────────────────────────────────

/** The manifests' texts as the edits leave them, each read once, written back together. */
class ManifestEdits {
  private readonly texts = new Map<string, string>();
  private readonly original = new Map<string, string>();
  private readonly ws: FixWorkspace;

  constructor(ws: FixWorkspace) {
    this.ws = ws;
  }

  get(file: string): string {
    const known = this.texts.get(file);
    if (known !== undefined) return known;
    const text = readText(this.ws, file);
    this.texts.set(file, text);
    this.original.set(file, text);
    return text;
  }

  set(file: string, text: string): void {
    this.get(file);
    this.texts.set(file, text);
  }

  write(): void {
    for (const [file, text] of this.texts) {
      if (text !== this.original.get(file)) writeText(this.ws, file, text);
    }
  }
}

/** The greatest target whose installed version the spec allows: what that spec resolved to. */
function targetFor(spec: string, targets: readonly FixTarget[]): string | null {
  const allowed = targets.filter((t) => rangeAllows(spec, t.installed)).map((t) => t.target);
  return greatestVersion('semver', allowed);
}

/** The specs of the package in a manifest's dependency sections. */
function declaredSpecs(manifest: Json, packageName: string): { section: string; spec: unknown }[] {
  return DIRECT_SECTIONS.flatMap((section) => {
    const deps = manifest[section];
    return isRecord(deps) && Object.hasOwn(deps, packageName)
      ? [{ section, spec: deps[packageName] }]
      : [];
  });
}

/**
 * Whether the fix is direct: a declared spec allows a vulnerable version, or has a shape Qualor
 * cannot rewrite (then `editDirect` says so, R22).
 */
function isDirect(
  edits: ManifestEdits,
  manifests: readonly string[],
  packageName: string,
  targets: readonly FixTarget[],
): boolean | FixStop {
  for (const file of manifests) {
    const manifest = parseManifest(edits.get(file));
    if (manifest === null) return unsupported(`${file} is not a JSON object.`);
    const direct = declaredSpecs(manifest, packageName).some(
      ({ spec }) =>
        typeof spec !== 'string' || !isRewritableRange(spec) || targetFor(spec, targets) !== null,
    );
    if (direct) return true;
  }
  return false;
}

function specText(spec: unknown): string {
  const text = typeof spec === 'string' ? spec : JSON.stringify(spec);
  return JSON.stringify(text.length > 120 ? `${text.slice(0, 120)}…` : text);
}

/** One manifest: each declared spec that allows a vulnerable version is raised to its target. */
function editManifest(
  edits: ManifestEdits,
  file: string,
  packageName: string,
  targets: readonly FixTarget[],
): FixStop | null {
  const manifest = parseManifest(edits.get(file));
  if (manifest === null) return unsupported(`${file} is not a JSON object.`);
  for (const { section, spec } of declaredSpecs(manifest, packageName)) {
    if (typeof spec !== 'string' || !isRewritableRange(spec)) {
      return unsupported(
        `${file} declares ${packageName} as ${specText(spec)} in ${section}; Qualor rewrites only a ^, ~, >= or = range or an exact version.`,
      );
    }
    const target = targetFor(spec, targets);
    const next = target === null ? null : rangeWithTarget(spec, target);
    if (next === null || next === spec) continue;
    const text = setJsonString(edits.get(file), [section, packageName], next);
    if (text === null) return unsupported(`${file}: cannot edit ${section}.${packageName}.`);
    edits.set(file, text);
  }
  return null;
}

function editDirect(
  edits: ManifestEdits,
  manifests: readonly string[],
  packageName: string,
  targets: readonly FixTarget[],
): FixStop | null {
  for (const file of manifests) {
    const stop = editManifest(edits, file, packageName, targets);
    if (stop !== null) return stop;
  }
  return null;
}

// ─── Pins (transitive) ──────────────────────────────────────────────────────

/** Where a lockfile's manager reads a pin, and the mechanism's name for the MR (R6). */
type Pin =
  | { file: string; kind: 'json'; path: readonly string[]; mechanism: string }
  | { file: string; kind: 'yaml'; mechanism: string };

function hasYamlOverrides(edits: ManifestEdits, file: string | null): boolean {
  if (file === null) return false;
  try {
    const doc: unknown = parseYaml(edits.get(file));
    return isRecord(doc) && Object.hasOwn(doc, 'overrides');
  } catch {
    return false;
  }
}

function pinOf(edits: ManifestEdits, project: Project, lockfile: Lockfile): Pin {
  const json = (pathTo: readonly string[], mechanism: string): Pin => ({
    file: project.manifest,
    kind: 'json',
    path: pathTo,
    mechanism,
  });
  if (lockfile.manager === 'npm') return json(['overrides'], 'overrides');
  if (lockfile.manager !== 'pnpm') return json(['resolutions'], 'resolutions');
  if (project.workspaceYaml !== null && hasYamlOverrides(edits, project.workspaceYaml)) {
    return { file: project.workspaceYaml, kind: 'yaml', mechanism: 'overrides' };
  }
  return json(['pnpm', 'overrides'], 'pnpm.overrides');
}

/** The greatest target of each release line of the installed versions. */
function targetsByLine(targets: readonly FixTarget[]): Map<string, string> {
  const byLine = new Map<string, string>();
  for (const t of targets) {
    const line = lineOf(t.installed);
    const known = byLine.get(line);
    if (known === undefined || bySemver(t.target, known) > 0) byLine.set(line, t.target);
  }
  return byLine;
}

/** R23: the versions of a release line, as npm and pnpm scope a pin (`0.x` lines by minor). */
function lineRange(line: string): string {
  if (line.startsWith('0.')) {
    const minor = Number(line.slice(2));
    return `>=0.${minor}.0 <0.${minor + 1}.0`;
  }
  const major = Number(line);
  return `>=${major}.0.0 <${major + 1}.0.0`;
}

/** Berry's descriptors (`pkg@npm:^1.2.0`) of the package's entries on one release line. */
function berryDescriptors(text: string, packageName: string, line: string): string[] {
  const lock: unknown = parseYaml(text, { schema: 'failsafe' });
  if (!isRecord(lock)) return [];
  const descriptors: string[] = [];
  for (const [key, entry] of Object.entries(lock)) {
    if (!isRecord(entry) || typeof entry['version'] !== 'string') continue;
    const resolution = entry['resolution'];
    const own = typeof resolution === 'string' && resolution.startsWith(`${packageName}@npm:`);
    if (!own || lineOf(entry['version']) !== line) continue;
    for (const descriptor of key.split(',').map((d) => d.trim())) {
      if (descriptor.startsWith(`${packageName}@`)) descriptors.push(descriptor);
    }
  }
  return descriptors;
}

/** Berry: one resolution per descriptor of each vulnerable line; null when one cannot be pinned. */
function berryKeys(
  text: string,
  packageName: string,
  byLine: ReadonlyMap<string, string>,
): Map<string, string> | null {
  const keys = new Map<string, string>();
  for (const [line, target] of byLine) {
    const descriptors = berryDescriptors(text, packageName, line);
    if (descriptors.length === 0 || !descriptors.every((d) => pinsPackage(d, packageName))) {
      return null;
    }
    for (const d of descriptors) keys.set(d, `^${target}`);
  }
  return keys;
}

function linesStop(
  lockfile: string,
  packageName: string,
  lines: readonly string[],
  why: string,
): FixStop {
  return severalLines(
    `${lockfile} resolves ${packageName} on several release lines (${listed(lines.map(lineName))}); ${why}`,
  );
}

/** The pin keys and values of one lockfile (R23), or why the lines cannot each be pinned. */
function pinKeys(
  ws: FixWorkspace,
  lockfile: Lockfile,
  packageName: string,
  targets: readonly FixTarget[],
): Map<string, string> | FixStop {
  const lines = [...new Set(versionsOf(lockEntries(ws, lockfile.path), packageName).map(lineOf))];
  const byLine = targetsByLine(targets);
  const greatest = greatestVersion('semver', [...byLine.values()]);
  if (greatest === null) return new Map<string, string>();
  if (lines.length <= 1) return new Map([[packageName, `^${greatest}`]]);
  if (lockfile.manager === 'yarn-classic') {
    return linesStop(
      lockfile.path,
      packageName,
      lines,
      'Yarn classic resolutions cannot pin each line to its own version.',
    );
  }
  if (lockfile.manager === 'yarn-berry') {
    return (
      berryKeys(readText(ws, lockfile.path), packageName, byLine) ??
      linesStop(lockfile.path, packageName, lines, 'Yarn cannot pin each line to its own version.')
    );
  }
  return new Map(
    [...byLine].map(([line, target]) => [`${packageName}@${lineRange(line)}`, `^${target}`]),
  );
}

/** The pins already in the container, by key. */
function existingPins(text: string, pin: Pin): Json {
  if (pin.kind === 'yaml') {
    const doc: unknown = parseYaml(text);
    return isRecord(doc) && isRecord(doc['overrides']) ? doc['overrides'] : {};
  }
  let value: unknown = parseManifest(text);
  for (const step of pin.path) value = isRecord(value) ? value[step] : undefined;
  return isRecord(value) ? value : {};
}

function setJsonPin(
  text: string,
  pin: Extract<Pin, { kind: 'json' }>,
  key: string,
  value: string,
  existing: Json,
): string | null {
  if (Object.hasOwn(existing, key)) {
    return typeof existing[key] === 'string'
      ? setJsonString(text, [...pin.path, key], value)
      : null;
  }
  try {
    return addJsonProperty(text, pin.path, key, value);
  } catch {
    return null;
  }
}

/** Writes the pins; a pin of the package under another key is a person's, left to them. */
function setPins(
  edits: ManifestEdits,
  pin: Pin,
  packageName: string,
  keys: ReadonlyMap<string, string>,
): FixStop | null {
  let text = edits.get(pin.file);
  const existing = existingPins(text, pin);
  const foreign = Object.keys(existing).filter((k) => pinsPackage(k, packageName) && !keys.has(k));
  if (foreign.length > 0) {
    return unsupported(
      `${pin.file} already pins ${packageName} with ${listed(foreign.map((k) => JSON.stringify(k)))}.`,
    );
  }
  for (const [key, value] of keys) {
    const next =
      pin.kind === 'yaml'
        ? setYamlOverride(text, key, value)
        : setJsonPin(text, pin, key, value, existing);
    if (next === null)
      return unsupported(
        `${pin.file}: cannot set the ${pin.mechanism} pin ${JSON.stringify(key)}.`,
      );
    text = next;
  }
  edits.set(pin.file, text);
  return null;
}

function pinTransitive(
  ws: FixWorkspace,
  edits: ManifestEdits,
  project: Project,
  packageName: string,
  targets: readonly FixTarget[],
): ProjectPlan | FixStop {
  const mechanisms = new Map<string, string | null>();
  for (const lockfile of project.lockfiles) {
    const pin = pinOf(edits, project, lockfile);
    mechanisms.set(lockfile.path, pin.mechanism);
    const keys = pinKeys(
      ws,
      lockfile,
      packageName,
      targets.filter((t) => t.lockfile === lockfile.path),
    );
    if (isStop(keys)) return keys;
    const stop = keys.size === 0 ? null : setPins(edits, pin, packageName, keys);
    if (stop !== null) return stop;
  }
  return { project, relation: 'transitive', mechanisms };
}

/** One project's edit: direct (its ranges) or transitive (its pins). */
function planProject(
  ws: FixWorkspace,
  edits: ManifestEdits,
  project: Project,
  fix: FixClaimItem,
  plan: FixPlan,
): ProjectPlan | FixStop {
  const targets = plan.targets.filter((t) => dirOf(t.lockfile) === project.dir);
  const manifests = [project.manifest, ...project.members];
  const direct = isDirect(edits, manifests, fix.packageName, targets);
  if (isStop(direct)) return direct;
  if (!direct) return pinTransitive(ws, edits, project, fix.packageName, targets);
  const stop = editDirect(edits, manifests, fix.packageName, targets);
  if (stop !== null) return stop;
  const mechanisms = new Map<string, string | null>(project.lockfiles.map((l) => [l.path, null]));
  return { project, relation: 'direct', mechanisms };
}

// ─── Package managers ───────────────────────────────────────────────────────

interface Command {
  tool: string;
  args: readonly string[];
  env: Readonly<Record<string, string>>;
  /** The stream the manager writes its errors to. */
  errors: 'stdout' | 'stderr';
}

/**
 * Berry: no scripts (ruling F20), no immutable installs in CI, no telemetry. Ruling T13g: git may
 * use no protocol (`GIT_ALLOW_PROTOCOL` names none that exists) and reads no system configuration,
 * so a git dependency that appears during the run (a new version's own dependency) cannot be
 * cloned or prepared; the run fails instead.
 */
const BERRY_ENV = {
  YARN_ENABLE_SCRIPTS: 'false',
  YARN_ENABLE_IMMUTABLE_INSTALLS: 'false',
  YARN_ENABLE_TELEMETRY: 'false',
  GIT_ALLOW_PROTOCOL: 'qualor-none',
  GIT_CONFIG_NOSYSTEM: '1',
} as const;

/** §6.5's lockfile regeneration per manager, scripts off (ruling F20); CI defaults turned off. */
const COMMANDS: Readonly<Record<Manager, Command>> = {
  npm: {
    tool: 'npm',
    args: ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'],
    env: {},
    errors: 'stderr',
  },
  pnpm: {
    tool: 'pnpm',
    args: ['install', '--lockfile-only', '--ignore-scripts', '--no-frozen-lockfile'],
    env: {},
    errors: 'stdout',
  },
  'yarn-classic': {
    tool: 'yarn',
    args: ['install', '--ignore-scripts', '--non-interactive'],
    env: {},
    errors: 'stderr',
  },
  'yarn-berry': {
    tool: 'yarn',
    args: ['install', '--mode=update-lockfile'],
    env: BERRY_ENV,
    errors: 'stdout',
  },
};

/**
 * Ruling F36: what each manager prints when no version satisfies a range: npm `ETARGET` (or
 * `ERESOLVE`), pnpm `ERR_PNPM_NO_MATCHING_VERSION`, Yarn classic "Couldn't find any versions",
 * Berry `YN0082` "No candidates found".
 */
const UNRESOLVABLE =
  /\b(?:ETARGET|ERESOLVE|ERR_PNPM_NO_MATCHING_VERSION|YN0082)\b|No candidates found|Couldn't find any versions for/;

const timeLeft = (ws: FixWorkspace) => Math.max(0, ws.deadline - Date.now());

function run(
  ws: FixWorkspace,
  dir: string,
  command: Command,
  args = command.args,
): Promise<ToolResult> {
  return ws.run(command.tool, args, {
    cwd: absolute(ws, dir),
    env: command.env,
    timeoutMs: timeLeft(ws),
  });
}

/** A manager that did not succeed: `no_fix unresolvable` (F36), else its failure (`toolFailure`). */
function resultStop(command: Command, r: ToolResult): FixStop | null {
  if (r.exitCode === 0 && !r.timedOut) return null;
  const first = command.errors === 'stdout' ? r.stdout : r.stderr;
  const output = first.trim() === '' ? `${r.stdout}${r.stderr}` : first;
  const failure = toolFailure(command.tool, { ...r, stderr: output }, []);
  if (!r.timedOut && UNRESOLVABLE.test(`${r.stdout}\n${r.stderr}`)) {
    return { kind: 'no_fix', reason: 'unresolvable', message: failure.message };
  }
  return { kind: 'failure', ...failure };
}

/** The `yarn` on PATH must be the lockfile's flavour, or it would convert the lockfile. */
async function yarnFlavourStop(ws: FixWorkspace, project: Project): Promise<FixStop | null> {
  const lockfile = project.lockfiles.find((l) => l.manager !== 'npm' && l.manager !== 'pnpm');
  if (lockfile === undefined) return null;
  const command = COMMANDS[lockfile.manager];
  const r = await run(ws, project.dir, command, ['--version']);
  const stop = resultStop(command, r);
  if (stop !== null) return stop;
  const version = r.stdout.trim().split(/\s/, 1)[0] ?? '';
  const classic = Number.parseInt(version, 10) === 1;
  if (classic === (lockfile.manager === 'yarn-classic')) return null;
  const want = lockfile.manager === 'yarn-classic' ? 'Yarn classic (1.x)' : 'Yarn 2 or later';
  return {
    kind: 'failure',
    code: 'missing_tool',
    message: `${lockfile.path} needs ${want}, but the yarn on PATH is ${version.slice(0, 40)}.`,
  };
}

/** The files of a project no manager may change but its own lockfile. */
function guarded(ws: FixWorkspace, project: Project, own: string): Map<string, string> {
  const files = [
    project.manifest,
    ...project.members,
    ...(project.workspaceYaml === null ? [] : [project.workspaceYaml]),
    ...project.lockfiles.map((l) => l.path).filter((p) => p !== own),
  ];
  return new Map(files.map((f) => [f, readText(ws, f)]));
}

function restore(ws: FixWorkspace, saved: ReadonlyMap<string, string>): void {
  for (const [file, text] of saved) {
    let now: string | null;
    try {
      now = readText(ws, file);
    } catch {
      now = null;
    }
    if (now !== text) writeText(ws, file, text);
  }
}

/** B7: every lockfile of the project, each by its manager, the project's other files kept. */
async function regenerate(ws: FixWorkspace, project: Project): Promise<FixStop | null> {
  for (const lockfile of project.lockfiles) {
    const keep = guarded(ws, project, lockfile.path);
    const command = COMMANDS[lockfile.manager];
    const r = await run(ws, project.dir, command);
    restore(ws, keep);
    const stop = resultStop(command, r);
    if (stop !== null) return stop;
  }
  return null;
}

// ─── Verify ─────────────────────────────────────────────────────────────────

function groupByLockfile(targets: readonly FixTarget[]): Map<string, FixTarget[]> {
  const out = new Map<string, FixTarget[]>();
  for (const t of targets) out.set(t.lockfile, [...(out.get(t.lockfile) ?? []), t]);
  return out;
}

/**
 * B3: an instance still below its target (`installed ≤ v < target`), or a line whose target stays
 * on it that no longer has any instance (its instance was pushed across a major).
 */
function lockfileProblems(
  lockfile: string,
  versions: readonly string[],
  targets: readonly FixTarget[],
): string[] {
  const problems: string[] = [];
  for (const v of versions) {
    const t = targets.find((x) => bySemver(x.installed, v) <= 0 && bySemver(v, x.target) < 0);
    if (t !== undefined) problems.push(`${lockfile} still resolves ${v}, below ${t.target}`);
  }
  for (const t of targets) {
    const line = lineOf(t.installed);
    if (line !== lineOf(t.target) || versions.some((v) => lineOf(v) === line)) continue;
    problems.push(
      `${lockfile} no longer resolves ${lineName(line)}: its ${t.installed} moved to another line`,
    );
  }
  return problems;
}

/** Re-reads the lockfiles (B3): null when every vulnerable instance reached its line's target. */
function verifyStop(ws: FixWorkspace, fix: FixClaimItem, plan: FixPlan): FixStop | null {
  const problems: string[] = [];
  const lines = new Set<string>();
  for (const [lockfile, targets] of groupByLockfile(plan.targets)) {
    const versions = versionsOf(lockEntries(ws, lockfile), fix.packageName);
    for (const v of [...versions, ...targets.map((t) => t.installed)]) lines.add(lineOf(v));
    problems.push(...lockfileProblems(lockfile, versions, targets));
  }
  if (problems.length === 0) return null;
  const named = listed([...lines].toSorted(compareLines).map(lineName));
  return severalLines(
    `${fix.packageName} is on the release lines ${named}, and the package manager did not move each to its own fixed version: ${problems.slice(0, 5).join('; ')}.`,
  );
}

/** Release lines (`1`, `0.2`) in numeric order. */
function compareLines(a: string, b: string): number {
  const [x, y] = [a.split('.').map(Number), b.split('.').map(Number)];
  return (x[0] ?? 0) - (y[0] ?? 0) || (x[1] ?? 0) - (y[1] ?? 0);
}

// ─── The adapter ────────────────────────────────────────────────────────────

function dependentsOf(entries: readonly LockEntry[], packageName: string): string[] {
  const names = entries.filter((e) => e.name === packageName).flatMap((e) => e.dependents);
  return [...new Set(names)]
    .filter((n) => n !== packageName)
    .toSorted()
    .slice(0, FIX_MAX_DEPENDENTS);
}

/** R6: each lockfile the managers changed, with its relation, pin and dependents. */
function lockfileLines(
  ws: FixWorkspace,
  packageName: string,
  plans: readonly ProjectPlan[],
  before: ReadonlyMap<string, string>,
): FixLockfile[] {
  return plans.flatMap(({ project, relation, mechanisms }) =>
    project.lockfiles
      .filter((l) => readText(ws, l.path) !== before.get(l.path))
      .map((l) => ({
        path: l.path,
        relation,
        mechanism: mechanisms.get(l.path) ?? null,
        dependents: dependentsOf(lockEntries(ws, l.path), packageName),
      })),
  );
}

async function firstStop<T>(
  items: readonly T[],
  step: (item: T) => Promise<FixStop | null>,
): Promise<FixStop | null> {
  for (const item of items) {
    const stop = await step(item);
    if (stop !== null) return stop;
  }
  return null;
}

function planAll(
  ws: FixWorkspace,
  edits: ManifestEdits,
  projects: readonly Project[],
  fix: FixClaimItem,
  plan: FixPlan,
): ProjectPlan[] | FixStop {
  const plans: ProjectPlan[] = [];
  for (const project of projects) {
    const planned = planProject(ws, edits, project, fix, plan);
    if (isStop(planned)) return planned;
    ws.log.debug(planLine(planned));
    plans.push(planned);
  }
  return plans;
}

/** One line for the job's log: where, and how the package is moved. */
function planLine({ project, relation, mechanisms }: ProjectPlan): string {
  const where = project.dir === '' ? 'the repository root' : project.dir;
  const how =
    relation === 'direct'
      ? 'raising the declared ranges'
      : `pinning through ${[...new Set(mechanisms.values())].join(' and ')}`;
  return `js fix in ${where}: ${how}, then regenerating ${project.lockfiles.map((l) => l.path).join(', ')}`;
}

async function apply(
  ws: FixWorkspace,
  fix: FixClaimItem,
  plan: FixPlan,
): Promise<AppliedFix | FixStop> {
  const projects = projectsOf(ws, plan);
  if (isStop(projects)) return projects;
  const refused =
    zeroInstallStop(ws, projects) ?? berrySourceStop(ws, projects) ?? berrySpecStop(ws, projects);
  if (refused !== null) return refused;
  const edits = new ManifestEdits(ws);
  const plans = planAll(ws, edits, projects, fix, plan);
  if (isStop(plans)) return plans;
  const flavour = await firstStop(projects, (p) => yarnFlavourStop(ws, p));
  if (flavour !== null) return flavour;
  edits.write();
  const lockfiles = projects.flatMap((p) => p.lockfiles.map((l) => l.path));
  const before = new Map(lockfiles.map((l) => [l, readText(ws, l)]));
  const failed = await firstStop(projects, (p) => regenerate(ws, p));
  if (failed !== null) return failed;
  return (
    verifyStop(ws, fix, plan) ?? { lockfiles: lockfileLines(ws, fix.packageName, plans, before) }
  );
}

/** A lockfile's versions of the package; none, with a warning, for a file the readers refuse. */
function installedIn(ws: FixWorkspace, lockfile: string, packageName: string): string[] {
  try {
    return versionsOf(lockEntries(ws, lockfile), packageName);
  } catch (err) {
    // A fixture or a broken lockfile elsewhere in the repository must not stop every JS fix.
    ws.log.warn(`skipping ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

/**
 * Every JS lockfile's versions of the package (not of aliases in its slot), via the shared readers;
 * a lockfile that is a link is not read.
 */
function installed(ws: FixWorkspace, packageName: string): Promise<InstalledAt[]> {
  const found = ws.files
    .filter((p) => isJsLockfile(p) && isRegularFile(ws, p))
    .toSorted()
    .map((lockfile) => ({ lockfile, versions: installedIn(ws, lockfile, packageName) }))
    .filter((at) => at.versions.length > 0);
  return Promise.resolve(found);
}

/** The JS family's adapter (Task 13): npm, pnpm, Yarn classic and Yarn Berry. */
export const jsAdapter: FixAdapter = {
  family: 'js',
  installed,
  apply,
  verify: (ws, fix, plan) => Promise.resolve(verifyStop(ws, fix, plan)),
};
