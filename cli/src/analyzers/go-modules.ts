import { readdirSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import type { ScopeFile } from '../discovery/discover';
import { isInside, staysInside, within } from './binary';
import { compareGoVersions, parseGoMod } from './go-mod';
import { deadProxyEnv } from './offline';
import { shown } from './reason';
import { readRepoConfig, WeblintConfigError } from './weblint';

/** config.md §6: a go.mod larger than this is not read. */
export const MAX_GO_MOD_BYTES = 1024 * 1024;
/** config.md §6: a module with more entries than this below it is not checked for links. */
export const MAX_MODULE_ENTRIES = 1_000_000;
export const TOO_MANY_ENTRIES = '\u0000too many entries';

export interface GoModule {
  /** Absolute. */
  dir: string;
  /** Repository-relative, `/`-separated; '' for the root. */
  rel: string;
  modulePath: string;
  /** In-scope Go files that belong to it. */
  files: number;
}

export interface GoModulePlan {
  modules: GoModule[];
  skipped: { rel: string; reason: string }[];
  /** In-scope Go files below no go.mod. */
  outside: number;
}

const repoPath = (root: string, abs: string) => path.relative(root, abs).split(path.sep).join('/');

/**
 * Names go itself never reads below a module (`go help packages`: directories, and files, whose
 * names start with `.` or `_`, and `testdata`), `.git` included.
 */
export function goIgnores(name: string): boolean {
  return name.startsWith('.') || name.startsWith('_') || name === 'testdata';
}

/**
 * Directories the link walk does not enter beyond goIgnores: only `node_modules`, where an `npm
 * link`ed package may point anywhere and go never looks. Ruling G9-19: every other built-in excluded
 * name (`build`, `dist`, `target`, `obj`, …) is an ordinary Go package directory go reads, so it is
 * walked; `vendor` is walked too. A link inside `node_modules` is not detected, an accepted cost.
 */
export const WALK_SKIPPED_DIRS: ReadonlySet<string> = new Set(['node_modules']);

/**
 * The first entry below `dirs` that is a symbolic link whose target lies outside the repository
 * (its repository path, as reached), TOO_MANY_ENTRIES, or null. Ruling G9-7: entries go ignores
 * (goIgnores) are skipped, directories in WALK_SKIPPED_DIRS and directories holding their own go.mod
 * (other modules) are not entered; `vendor/` is. A link with a WALK_SKIPPED_DIRS name is still
 * checked. A link to a directory inside the repository is entered too, whatever its target is
 * called: go reads through it (a vendored package linked into `node_modules/`), so the skips above
 * do not cover what it leads to. Each real directory is walked once, so links in a cycle and
 * repeated start directories cost nothing more. The 1,000,000-entry cap counts only what the walk
 * visits, across all of `dirs`. A dangling link is ignored: go cannot read through it either.
 */
export function escapingLink(dirs: string | readonly string[], root: string): string | null {
  const realRoot = realpathSync(root);
  const pending = typeof dirs === 'string' ? [dirs] : [...dirs].reverse();
  const walked = new Set<string>();
  let seen = 0;
  for (let d = pending.pop(); d !== undefined; d = pending.pop()) {
    let entries;
    try {
      const realDir = realpathSync(d);
      if (walked.has(realDir)) continue;
      walked.add(realDir);
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (goIgnores(e.name)) continue;
      if (e.isDirectory() && WALK_SKIPPED_DIRS.has(e.name)) continue;
      seen += 1;
      if (seen > MAX_MODULE_ENTRIES) return TOO_MANY_ENTRIES;
      const full = path.join(d, e.name);
      if (e.isSymbolicLink()) {
        let target: string;
        try {
          target = realpathSync(full);
        } catch {
          continue;
        }
        if (!within(realRoot, target)) return repoPath(root, full);
        if (isDirectory(target)) pending.push(full);
      } else if (e.isDirectory() && !holdsGoMod(full)) {
        pending.push(full);
      }
    }
  }
  return null;
}

function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function checkModule(
  root: string,
  rel: string,
  goVersion: string,
): Omit<GoModule, 'files'> | string {
  const goModRel = rel === '' ? 'go.mod' : `${rel}/go.mod`;
  let text: string;
  try {
    text = readRepoConfig(root, goModRel, MAX_GO_MOD_BYTES);
  } catch (err) {
    if (err instanceof WeblintConfigError) return err.message;
    throw err;
  }
  const mod = parseGoMod(text);
  if ('error' in mod) return `${goModRel} cannot be read: ${mod.error}`;
  if (mod.module === null) return `${goModRel} names no module`;
  if (mod.go !== null && compareGoVersions(mod.go, goVersion) > 0) {
    return `${goModRel} needs Go ${shown(mod.go)}, newer than this Go ${goVersion}; Qualor never downloads a toolchain (GOTOOLCHAIN=local)`;
  }
  const dir = rel === '' ? root : path.join(root, ...rel.split('/'));
  // go reads a directory replacement as source, so it is walked for links out like the module.
  const replaced: string[] = [];
  for (const r of mod.replaces) {
    if (r.targetVersion !== null) continue;
    const target = path.resolve(dir, r.target);
    if (!staysInside(root, target)) {
      return `${goModRel} replaces ${shown(r.old)} with ${shown(r.target)}, a directory outside the repository, which Qualor does not read`;
    }
    replaced.push(target);
  }
  const link = escapingLink([dir, ...replaced], root);
  if (link === TOO_MANY_ENTRIES) {
    return `more than ${MAX_MODULE_ENTRIES} entries below ${rel === '' ? 'the root' : shown(rel)}: not checked for links, so not analysed`;
  }
  if (link !== null)
    return `${shown(link)} is a symbolic link out of the repository, which Go would follow`;
  return { dir, rel, modulePath: mod.module };
}

/**
 * True when the directory `dir` holds a go.mod go would take: an entry that is not a directory once
 * links are followed. A dangling link is none, as for go; a link out of the repository is one, and
 * checkModule then refuses it.
 */
function holdsGoMod(dir: string): boolean {
  try {
    return !statSync(path.join(dir, 'go.mod')).isDirectory();
  } catch {
    return false;
  }
}

/** config.md §6: the scan's Go modules, each with the in-scope Go files below it, or why not. */
export function planGoModules(
  root: string,
  files: readonly ScopeFile[],
  goVersion: string,
): GoModulePlan {
  // Ruling G9-19: the owner is the nearest go.mod on disk at or above the file's directory, as go
  // finds it, whether or not the go.mod itself is in scope (`sources.include` may name only .go
  // files); checkModule reads it through readRepoConfig.
  const owners = new Map<string, string | null>();
  const ownerOf = (dir: string): string | null => {
    const known = owners.get(dir);
    if (known !== undefined) return known;
    const owner = holdsGoMod(dir === '' ? root : path.join(root, ...dir.split('/')))
      ? dir
      : dir === ''
        ? null
        : ownerOf(dir.includes('/') ? dir.slice(0, dir.lastIndexOf('/')) : '');
    owners.set(dir, owner);
    return owner;
  };
  const counts = new Map<string, number>();
  let outside = 0;
  for (const f of files) {
    if (f.language !== 'go') continue;
    const owner = ownerOf(f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '');
    if (owner === null) outside += 1;
    else counts.set(owner, (counts.get(owner) ?? 0) + 1);
  }
  const modules: GoModule[] = [];
  const skipped: { rel: string; reason: string }[] = [];
  for (const rel of [...counts.keys()].sort()) {
    const checked = checkModule(root, rel, goVersion);
    if (typeof checked === 'string') skipped.push({ rel, reason: checked });
    else modules.push({ ...checked, files: counts.get(rel) as number });
  }
  return { modules, skipped, outside };
}

/**
 * config.md §6: the module cache the tools read, never written by Qualor itself: the CI's
 * GOMODCACHE, else the first GOPATH entry's pkg/mod, else $HOME/go/pkg/mod (the CLI's own
 * environment). A relative one, or none, gives an empty cache in the work directory; one inside the
 * repository is refused with a warning (a merge request could plant a fake cache there).
 */
export function goModuleCache(
  env: Readonly<Record<string, string | undefined>>,
  root: string,
  workDir: string,
): { dir: string; warning: string | null } {
  const own = path.join(workDir, 'gomodcache');
  const gopath = env['GOPATH']?.split(path.delimiter).find((p) => p !== '');
  const home = env['HOME'];
  const candidate =
    env['GOMODCACHE'] ||
    (gopath !== undefined
      ? path.join(gopath, 'pkg', 'mod')
      : home
        ? path.join(home, 'go', 'pkg', 'mod')
        : '');
  if (candidate === '' || !path.isAbsolute(candidate)) return { dir: own, warning: null };
  if (isInside(root, candidate)) {
    return {
      dir: own,
      warning: `the Go module cache ${shown(candidate)} is inside the repository and is not used (config.md §6); keep it outside, for example GOMODCACHE=/tmp/gomodcache`,
    };
  }
  return { dir: candidate, warning: null };
}

/** config.md §6: the only inherited variables the go command and the Go tools see (matched without case). */
export const GO_KEPT_ENV: ReadonlySet<string> = new Set([
  'PATH',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'SYSTEMROOT',
  'WINDIR',
]);

/** config.md §6: Qualor's own variables for the Go runner and every command it starts. */
export function goEnv(o: {
  workDir: string;
  go: string;
  moduleCache: string;
  path: string | undefined;
}): Record<string, string> {
  return {
    ...deadProxyEnv(),
    PATH: [path.dirname(o.go), o.path ?? ''].filter((p) => p !== '').join(path.delimiter),
    HOME: o.workDir,
    LC_ALL: 'C.UTF-8',
    GOTOOLCHAIN: 'local',
    GOPROXY: 'off',
    GOFLAGS: '',
    GOWORK: 'off',
    GOENV: 'off',
    GOVCS: '*:off',
    CGO_ENABLED: '0',
    GOPACKAGESDRIVER: 'off',
    GOCACHE: path.join(o.workDir, 'gocache'),
    GOPATH: path.join(o.workDir, 'gopath'),
    GOMODCACHE: o.moduleCache,
    XDG_CACHE_HOME: path.join(o.workDir, 'cache'),
    XDG_CONFIG_HOME: path.join(o.workDir, 'config'),
  };
}
